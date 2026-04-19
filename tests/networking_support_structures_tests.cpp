// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <atomic>
#include <cstdint>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "macros/time.h"
#include "types/types.containers.h"
#include "networking/pool.h"
#include "networking/timerwheel.h"
#include "networking/coroutinestack.h"
#include "networking/multiplexer.h"
#include "networking/socket.h"
#include "networking/stream.h"
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#endif
#define private public
#include "networking/ring.h"
#undef private
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

namespace {

struct RecordingTimerEvent : TimerEventInterface {
  int id;
  std::vector<int> *executions;

  explicit RecordingTimerEvent(int value, std::vector<int>& target)
      : id(value),
        executions(&target)
  {}

  void execute() override
  {
    executions->push_back(id);
  }
};

struct TimeoutDispatchRecorder : TimeoutDispatcher {
  int dispatched = 0;
  TimeoutPacket *lastPacket = nullptr;

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    ++dispatched;
    lastPacket = packet;
  }
};

struct RecordingRingInterface : RingInterface {
  int acceptCalls = 0;
  int closeCalls = 0;
  int recvCalls = 0;
  int pollCalls = 0;
  int timeoutCalls = 0;
  int waitidCalls = 0;
  int lastAcceptSlot = -1;
  int lastRecvResult = 0;
  int lastPollResult = 0;
  int lastTimeoutResult = 0;
  void *lastSocket = nullptr;
  void *lastWaiter = nullptr;
  TimeoutPacket *lastTimeoutPacket = nullptr;

  void acceptHandler(void *socket, int fslot) override
  {
    ++acceptCalls;
    lastSocket = socket;
    lastAcceptSlot = fslot;
  }

  void closeHandler(void *socket) override
  {
    ++closeCalls;
    lastSocket = socket;
  }

  void recvHandler(void *socket, int result) override
  {
    ++recvCalls;
    lastSocket = socket;
    lastRecvResult = result;
  }

  void pollHandler(void *socket, int result) override
  {
    ++pollCalls;
    lastSocket = socket;
    lastPollResult = result;
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    ++timeoutCalls;
    lastTimeoutPacket = packet;
    lastTimeoutResult = result;
  }

  void waitidHandler(void *waiter) override
  {
    ++waitidCalls;
    lastWaiter = waiter;
  }
};

struct RecordingMultiplexer : RingMultiplexer {
  int beforeCount = 0;
  int afterCount = 0;
  int signalCount = 0;
  bool signalReturn = true;

  void beforeRing(void) override
  {
    ++beforeCount;
  }

  void afterRing(void) override
  {
    ++afterCount;
  }

  bool signalHandler(const struct signalfd_siginfo&) override
  {
    ++signalCount;
    return signalReturn;
  }
};

struct DispatcherScope {
  RingDispatcher *savedDispatcher = nullptr;
  RingInterface *savedInterfacer = nullptr;
  RingLifecycle *savedLifecycler = nullptr;
  RingDispatcher localDispatcher;

  DispatcherScope()
      : savedDispatcher(RingDispatcher::dispatcher),
        savedInterfacer(ringInterfacer),
        savedLifecycler(ringLifecycler)
  {
  }

  ~DispatcherScope()
  {
    RingDispatcher::dispatcher = savedDispatcher;
    ringInterfacer = savedInterfacer;
    ringLifecycler = savedLifecycler;
  }
};

struct DestructionProbe {
  int *counter;

  explicit DestructionProbe(int *target)
      : counter(target)
  {}

  ~DestructionProbe()
  {
    ++(*counter);
  }
};

static void clearRingCloseTrackingState(void)
{
  Ring::linkTimeoutTrackingByUserData.clear();
  Ring::retiredLinkTimeoutTrackingUserData.clear();
  Ring::closeTrackingByUserData.clear();
  Ring::retiredCloseTrackingUserData.clear();
  Ring::isClosing.clear();
  Ring::closingSerialByIdentity.clear();
  Ring::socketGenerationByIdentity.clear();
  Ring::nextLinkTimeoutTicket = 1;
  Ring::nextCloseSerial = 1;
  Ring::nextCloseTicket = 1;
  Ring::retiredLinkTimeoutTrackingHistory.fill(0);
  Ring::retiredLinkTimeoutTrackingHead = 0;
  Ring::retiredLinkTimeoutTrackingUserDataCount = 0;
  Ring::retiredCloseTrackingHistory.fill(0);
  Ring::retiredCloseTrackingHead = 0;
  Ring::retiredCloseTrackingUserDataCount = 0;
}

static void singleSuspend(CoroutineStack& stack, std::vector<int>& steps, int id)
{
  steps.push_back((id * 10) + 1);
  co_await stack.suspend();
  steps.push_back((id * 10) + 2);
}

static void indexedSuspend(CoroutineStack& stack, std::vector<int>& steps, int id, uint32_t index)
{
  steps.push_back((id * 10) + 1);
  co_await stack.suspendAtIndex(index);
  steps.push_back((id * 10) + 2);
}

static void twoStageSuspend(CoroutineStack& stack, std::vector<int>& steps)
{
  steps.push_back(1);
  co_await stack.suspend();
  steps.push_back(2);
  co_await stack.suspend();
  steps.push_back(3);
}

static void suspendUsRunThisCoroutine(CoroutineStack& stack, std::vector<int>& steps)
{
  co_await stack.suspendUsRunThis([&]() {
    steps.push_back(1);
  });
  steps.push_back(2);
}

static void cancellableCoroutine(CoroutineStack& stack, int *destructionCount)
{
  DestructionProbe probe(destructionCount);
  co_await stack.suspend();
}

static void testPoolReuseAndOutstandingTracking(TestSuite& suite)
{
  Pool<int> pool(2);
  int *first = pool.get();
  int *second = pool.get();
  int *empty = pool.get();

  EXPECT_TRUE(suite, first != nullptr);
  EXPECT_TRUE(suite, second != nullptr);
  EXPECT_FALSE(suite, first == second);
  EXPECT_TRUE(suite, empty == nullptr);

  *first = 11;
  *second = 22;

  pool.relinquish(first);
  pool.relinquish(second);

  int *reusedSecond = pool.get();
  int *reusedFirst = pool.get();

  EXPECT_TRUE(suite, reusedSecond == second);
  EXPECT_TRUE(suite, reusedFirst == first);
  EXPECT_EQ(suite, *reusedSecond, 22);
  EXPECT_EQ(suite, *reusedFirst, 11);

  Pool<int, false, true> tracked(1);
  int *trackedItem = tracked.get();
  EXPECT_TRUE(suite, trackedItem != nullptr);
  EXPECT_EQ(suite, tracked.outstandingCount(), uint32_t(1));
  EXPECT_TRUE(suite, tracked.contains(trackedItem));

  int *failed = tracked.get();
  EXPECT_TRUE(suite, failed == nullptr);
  EXPECT_EQ(suite, tracked.outstandingCount(), uint32_t(1));
  EXPECT_FALSE(suite, tracked.contains(nullptr));

  Vector<int *> outstandingItems;
  tracked.forOutstanding([&](int *item) {
    outstandingItems.push_back(item);
  });
  EXPECT_EQ(suite, outstandingItems.size(), uint64_t(1));
  EXPECT_TRUE(suite, outstandingItems[0] == trackedItem);

  tracked.relinquish(nullptr);
  EXPECT_EQ(suite, tracked.outstandingCount(), uint32_t(1));

  tracked.relinquish(trackedItem);
  EXPECT_EQ(suite, tracked.outstandingCount(), uint32_t(0));
  EXPECT_FALSE(suite, tracked.contains(trackedItem));

  Pool<int, true, true> overflowing(1);
  int *baseItem = overflowing.get();
  int *overflowItem = overflowing.get();
  EXPECT_TRUE(suite, baseItem != nullptr);
  EXPECT_TRUE(suite, overflowItem != nullptr);
  EXPECT_FALSE(suite, baseItem == overflowItem);
  EXPECT_EQ(suite, overflowing.outstandingCount(), uint32_t(2));
  overflowing.relinquish(baseItem);
  overflowing.relinquish(overflowItem);
  EXPECT_EQ(suite, overflowing.outstandingCount(), uint32_t(0));

  Pool<int, true, true> reinitialized(1);
  int *firstGeneration = reinitialized.get();
  EXPECT_TRUE(suite, firstGeneration != nullptr);
  reinitialized.relinquish(firstGeneration);
  reinitialized.initialize(2);
  EXPECT_EQ(suite, reinitialized.outstandingCount(), uint32_t(0));
  int *reinitializedA = reinitialized.get();
  int *reinitializedB = reinitialized.get();
  int *reinitializedOverflow = reinitialized.get();
  EXPECT_TRUE(suite, reinitializedA != nullptr);
  EXPECT_TRUE(suite, reinitializedB != nullptr);
  EXPECT_TRUE(suite, reinitializedOverflow != nullptr);
  EXPECT_FALSE(suite, reinitializedA == reinitializedB);
  reinitialized.relinquish(reinitializedA);
  reinitialized.relinquish(reinitializedB);
  reinitialized.relinquish(reinitializedOverflow);
  EXPECT_EQ(suite, reinitialized.outstandingCount(), uint32_t(0));
}

static void testMemoryPoolsReuseBuffers(TestSuite& suite)
{
  constexpr uint64_t bufferSize = 4096;

  {
    InvariantMemoryPool pool(bufferSize, 1);
    Buffer first;
    pool.fillBuffer(first);
    uint8_t *firstData = first.data();
    EXPECT_TRUE(suite, firstData != nullptr);
    EXPECT_EQ(suite, first.tentativeCapacity(), bufferSize);

    const uint8_t bytes[] = {'a', 'b', 'c'};
    first.append(bytes, sizeof(bytes));
    EXPECT_EQ(suite, first.size(), uint64_t(sizeof(bytes)));

    pool.relinquishBuffer(first);
    EXPECT_TRUE(suite, first.data() == nullptr);
    EXPECT_EQ(suite, first.size(), uint64_t(0));

    Buffer reused;
    pool.fillBuffer(reused);
    EXPECT_TRUE(suite, reused.data() == firstData);
    EXPECT_EQ(suite, reused.tentativeCapacity(), bufferSize);
    reused.append(bytes, sizeof(bytes));
    EXPECT_EQ(suite, reused.size(), uint64_t(sizeof(bytes)));
    pool.relinquishBuffer(reused);
  }

  {
    FlexibleMemoryPool pool(bufferSize, 1);
    Buffer first;
    pool.fillBuffer(first);
    uint8_t *firstData = first.data();
    EXPECT_TRUE(suite, firstData != nullptr);
    EXPECT_EQ(suite, first.tentativeCapacity(), bufferSize);

    const uint8_t bytes[] = {'x', 'y', 'z', '!'};
    first.append(bytes, sizeof(bytes));
    EXPECT_EQ(suite, first.size(), uint64_t(sizeof(bytes)));

    pool.relinquishBuffer(first);
    EXPECT_TRUE(suite, first.data() == nullptr);
    EXPECT_EQ(suite, first.size(), uint64_t(0));

    Buffer reused;
    pool.fillBuffer(reused);
    EXPECT_TRUE(suite, reused.data() == firstData);
    EXPECT_EQ(suite, reused.tentativeCapacity(), bufferSize);
    reused.append(bytes, sizeof(bytes));
    EXPECT_EQ(suite, reused.size(), uint64_t(sizeof(bytes)));
    pool.relinquishBuffer(reused);
  }
}

static void testTimerWheelSchedulingAndCancellation(TestSuite& suite)
{
  std::vector<int> executions;
  TimerWheel wheel(100);

  RecordingTimerEvent soon(1, executions);
  wheel.schedule(&soon, 5);
  EXPECT_TRUE(suite, soon.active());
  EXPECT_EQ(suite, soon.scheduled_at(), Tick(105));
  EXPECT_EQ(suite, wheel.ticks_to_next_event(), Tick(5));

  EXPECT_TRUE(suite, wheel.advance(4));
  EXPECT_TRUE(suite, executions.empty());
  EXPECT_EQ(suite, wheel.now(), Tick(104));
  EXPECT_EQ(suite, wheel.ticks_to_next_event(), Tick(1));

  EXPECT_TRUE(suite, wheel.advance(1));
  EXPECT_EQ(suite, executions.size(), size_t(1));
  EXPECT_EQ(suite, executions[0], 1);
  EXPECT_FALSE(suite, soon.active());

  executions.clear();
  RecordingTimerEvent rescheduled(2, executions);
  wheel.schedule(&rescheduled, 10);
  wheel.schedule(&rescheduled, 3);
  EXPECT_EQ(suite, rescheduled.scheduled_at(), Tick(108));
  EXPECT_EQ(suite, wheel.ticks_to_next_event(), Tick(3));
  EXPECT_TRUE(suite, wheel.advance(2));
  EXPECT_TRUE(suite, executions.empty());
  rescheduled.cancel();
  EXPECT_FALSE(suite, rescheduled.active());
  EXPECT_TRUE(suite, wheel.advance(2));
  EXPECT_TRUE(suite, executions.empty());

  RecordingTimerEvent zeroDelay(3, executions);
  wheel.schedule(&zeroDelay, 0);
  EXPECT_EQ(suite, wheel.ticks_to_next_event(), Tick(1));
  EXPECT_TRUE(suite, wheel.advance(1));
  EXPECT_EQ(suite, executions.size(), size_t(1));
  EXPECT_EQ(suite, executions[0], 3);

  executions.clear();
  TimerWheel promotedWheel(0);
  RecordingTimerEvent promoted(4, executions);
  promotedWheel.schedule(&promoted, 300);
  EXPECT_EQ(suite, promotedWheel.ticks_to_next_event(), Tick(300));
  EXPECT_TRUE(suite, promotedWheel.advance(299));
  EXPECT_TRUE(suite, executions.empty());
  EXPECT_TRUE(suite, promotedWheel.advance(1));
  EXPECT_EQ(suite, executions.size(), size_t(1));
  EXPECT_EQ(suite, executions[0], 4);

  executions.clear();
  TimerWheel orderingWheel(0);
  RecordingTimerEvent first(5, executions);
  RecordingTimerEvent second(6, executions);
  orderingWheel.schedule(&first, 2);
  orderingWheel.schedule(&second, 2);
  EXPECT_TRUE(suite, orderingWheel.advance(2));
  EXPECT_EQ(suite, executions.size(), size_t(2));
  EXPECT_EQ(suite, executions[0], 6);
  EXPECT_EQ(suite, executions[1], 5);
}

static void testRingDispatcherRoutesHandlers(TestSuite& suite)
{
  DispatcherScope scope;
  EXPECT_TRUE(suite, RingDispatcher::dispatcher == &scope.localDispatcher);
  EXPECT_TRUE(suite, ringInterfacer == &scope.localDispatcher);
  EXPECT_TRUE(suite, ringLifecycler == &scope.localDispatcher);

  RecordingRingInterface interfaceTarget;
  RecordingMultiplexer multiplexer;

  RingDispatcher::installMultiplexer(&multiplexer);

  scope.localDispatcher.beforeRing();
  scope.localDispatcher.afterRing();
  EXPECT_EQ(suite, multiplexer.beforeCount, 1);
  EXPECT_EQ(suite, multiplexer.afterCount, 1);

  signalfd_siginfo signalInfo = {};
  EXPECT_TRUE(suite, scope.localDispatcher.signalHandler(signalInfo));
  EXPECT_EQ(suite, multiplexer.signalCount, 1);

  multiplexer.signalReturn = false;
  EXPECT_FALSE(suite, scope.localDispatcher.signalHandler(signalInfo));
  EXPECT_EQ(suite, multiplexer.signalCount, 2);

  int socketToken = 17;
  int waiterToken = 23;
  RingDispatcher::installMultiplexee(&socketToken, &interfaceTarget);
  RingDispatcher::installMultiplexee(&waiterToken, &interfaceTarget);

  scope.localDispatcher.acceptHandler(&socketToken, 9);
  EXPECT_EQ(suite, interfaceTarget.acceptCalls, 1);
  EXPECT_TRUE(suite, interfaceTarget.lastSocket == &socketToken);
  EXPECT_EQ(suite, interfaceTarget.lastAcceptSlot, 9);

  scope.localDispatcher.recvHandler(&socketToken, 41);
  EXPECT_EQ(suite, interfaceTarget.recvCalls, 1);
  EXPECT_EQ(suite, interfaceTarget.lastRecvResult, 41);

  scope.localDispatcher.pollHandler(&socketToken, 77);
  EXPECT_EQ(suite, interfaceTarget.pollCalls, 1);
  EXPECT_EQ(suite, interfaceTarget.lastPollResult, 77);

  TimeoutPacket packet;
  packet.originator = &socketToken;
  scope.localDispatcher.timeoutHandler(&packet, 88);
  EXPECT_EQ(suite, interfaceTarget.timeoutCalls, 1);
  EXPECT_TRUE(suite, interfaceTarget.lastTimeoutPacket == &packet);
  EXPECT_EQ(suite, interfaceTarget.lastTimeoutResult, 88);

  TimeoutDispatchRecorder timeoutDispatcher;
  packet.dispatcher = &timeoutDispatcher;
  scope.localDispatcher.timeoutHandler(&packet, 99);
  EXPECT_EQ(suite, timeoutDispatcher.dispatched, 1);
  EXPECT_TRUE(suite, timeoutDispatcher.lastPacket == &packet);
  EXPECT_EQ(suite, interfaceTarget.timeoutCalls, 1);

  scope.localDispatcher.timeoutHandler(nullptr, 123);
  EXPECT_EQ(suite, timeoutDispatcher.dispatched, 1);
  EXPECT_EQ(suite, interfaceTarget.timeoutCalls, 1);

  scope.localDispatcher.waitidHandler(&waiterToken);
  EXPECT_EQ(suite, interfaceTarget.waitidCalls, 1);
  EXPECT_TRUE(suite, interfaceTarget.lastWaiter == &waiterToken);

  RingDispatcher::eraseMultiplexee(&socketToken);
  scope.localDispatcher.closeHandler(&socketToken);
  EXPECT_EQ(suite, interfaceTarget.closeCalls, 0);
}

static void testRingDispatcherIsThreadLocal(TestSuite& suite)
{
  DispatcherScope scope;

  RecordingRingInterface mainTarget;
  int mainToken = 17;
  RingDispatcher::installMultiplexee(&mainToken, &mainTarget);

  RecordingRingInterface workerTarget;
  int workerToken = 29;
  std::atomic<bool> workerUsedMainDispatcher = true;

  std::thread worker([&]() {
    RingDispatcher::installMultiplexee(&workerToken, &workerTarget);
    workerUsedMainDispatcher.store(RingDispatcher::dispatcher == &scope.localDispatcher, std::memory_order_release);
    RingDispatcher::dispatcher->recvHandler(&workerToken, 123);
  });
  worker.join();

  EXPECT_FALSE(suite, workerUsedMainDispatcher.load(std::memory_order_acquire));
  EXPECT_EQ(suite, workerTarget.recvCalls, 1);
  EXPECT_TRUE(suite, workerTarget.lastSocket == &workerToken);
  EXPECT_EQ(suite, workerTarget.lastRecvResult, 123);

  scope.localDispatcher.recvHandler(&workerToken, 77);
  EXPECT_EQ(suite, workerTarget.recvCalls, 1);

  scope.localDispatcher.recvHandler(&mainToken, 41);
  EXPECT_EQ(suite, mainTarget.recvCalls, 1);
  EXPECT_TRUE(suite, mainTarget.lastSocket == &mainToken);
  EXPECT_EQ(suite, mainTarget.lastRecvResult, 41);
}

static void testFallbackDispatcherInitDoesNotClobberLiveDispatcher(TestSuite& suite)
{
  std::atomic<bool> dispatcherStartsLocal = false;
  std::atomic<bool> dispatcherStaysLocal = false;
  std::atomic<bool> interfacerStaysLocal = false;
  std::atomic<bool> lifecyclerStaysLocal = false;

  std::thread worker([&]() {
    RingDispatcher localDispatcher;
    dispatcherStartsLocal.store(RingDispatcher::dispatcher == &localDispatcher, std::memory_order_release);

    Ring::interfacer = RingDispatcher::dispatcher;
    Ring::lifecycler = RingDispatcher::dispatcher;

    dispatcherStaysLocal.store(RingDispatcher::dispatcher == &localDispatcher, std::memory_order_release);
    interfacerStaysLocal.store(Ring::interfacer == static_cast<RingInterface *>(&localDispatcher), std::memory_order_release);
    lifecyclerStaysLocal.store(Ring::lifecycler == static_cast<RingLifecycle *>(&localDispatcher), std::memory_order_release);
  });
  worker.join();

  EXPECT_TRUE(suite, dispatcherStartsLocal.load(std::memory_order_acquire));
  EXPECT_TRUE(suite, dispatcherStaysLocal.load(std::memory_order_acquire));
  EXPECT_TRUE(suite, interfacerStaysLocal.load(std::memory_order_acquire));
  EXPECT_TRUE(suite, lifecyclerStaysLocal.load(std::memory_order_acquire));
}

static void testCoroutineStackScheduling(TestSuite& suite)
{
  {
    CoroutineStack stack;
    std::vector<int> steps;

    singleSuspend(stack, steps, 1);
    singleSuspend(stack, steps, 2);
    EXPECT_EQ(suite, steps.size(), size_t(2));
    EXPECT_EQ(suite, steps[0], 11);
    EXPECT_EQ(suite, steps[1], 21);
    EXPECT_TRUE(suite, stack.hasSuspendedCoroutines());

    stack.runNextSuspended();
    EXPECT_EQ(suite, steps.size(), size_t(3));
    EXPECT_EQ(suite, steps[2], 22);

    stack.runNextSuspended();
    EXPECT_EQ(suite, steps.size(), size_t(4));
    EXPECT_EQ(suite, steps[3], 12);
    EXPECT_FALSE(suite, stack.hasSuspendedCoroutines());
  }

  {
    CoroutineStack stack;
    std::vector<int> steps;

    singleSuspend(stack, steps, 1);
    singleSuspend(stack, steps, 2);
    indexedSuspend(stack, steps, 3, 0);

    stack.runNextSuspended();
    stack.runNextSuspended();
    stack.runNextSuspended();

    EXPECT_EQ(suite, steps.size(), size_t(6));
    EXPECT_EQ(suite, steps[0], 11);
    EXPECT_EQ(suite, steps[1], 21);
    EXPECT_EQ(suite, steps[2], 31);
    EXPECT_EQ(suite, steps[3], 22);
    EXPECT_EQ(suite, steps[4], 12);
    EXPECT_EQ(suite, steps[5], 32);
  }

  {
    CoroutineStack stack;
    std::vector<int> steps;

    suspendUsRunThisCoroutine(stack, steps);
    EXPECT_EQ(suite, steps.size(), size_t(1));
    EXPECT_EQ(suite, steps[0], 1);
    EXPECT_TRUE(suite, stack.hasSuspendedCoroutines());

    stack.runNextSuspended();
    EXPECT_EQ(suite, steps.size(), size_t(2));
    EXPECT_EQ(suite, steps[1], 2);
  }

  {
    CoroutineStack stack;
    std::vector<int> steps;

    twoStageSuspend(stack, steps);
    EXPECT_EQ(suite, steps.size(), size_t(1));
    EXPECT_EQ(suite, steps[0], 1);
    stack.co_consume();
    EXPECT_EQ(suite, steps.size(), size_t(2));
    EXPECT_EQ(suite, steps[1], 2);
    EXPECT_TRUE(suite, stack.hasSuspendedCoroutines());

    stack.co_consume();
    EXPECT_EQ(suite, steps.size(), size_t(3));
    EXPECT_EQ(suite, steps[2], 3);
    EXPECT_FALSE(suite, stack.hasSuspendedCoroutines());
  }

  {
    CoroutineStack stack;
    int destructionCount = 0;

    cancellableCoroutine(stack, &destructionCount);
    EXPECT_TRUE(suite, stack.hasSuspendedCoroutines());
    stack.cancelSuspended();
    EXPECT_FALSE(suite, stack.hasSuspendedCoroutines());
    EXPECT_EQ(suite, destructionCount, 1);
  }
}

static void testResolveTrackedCloseCompletionReturnsTracking(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 42;
  Ring::noteSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(9));

  const uint64_t userData = Ring::issueCloseTracking(socketKey, 37, 9, stream.ioGeneration);
  Ring::CloseCompletionTracking tracking = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedCloseCompletion(userData, tracking));
  EXPECT_TRUE(suite, tracking.socket == socketKey);
  EXPECT_EQ(suite, tracking.slot, 37);
  EXPECT_EQ(suite, tracking.serial, uint64_t(9));
  EXPECT_EQ(suite, tracking.generation, uint8_t(42));
  EXPECT_TRUE(suite, Ring::closeTrackingByUserData.find(userData) == Ring::closeTrackingByUserData.end());

  clearRingCloseTrackingState();
}

static void testTrackedCloseCompletionSkipsReusedGeneration(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 41;
  Ring::noteSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(5));

  stream.reset();
  Ring::noteSocketGeneration(&stream);

  EXPECT_FALSE(suite, Ring::shouldDispatchTrackedCloseCompletion(socketKey, uint64_t(5), uint8_t(41)));
  EXPECT_TRUE(suite, Ring::isClosing.contains(socketKey) == false);
  EXPECT_TRUE(suite, Ring::closingSerialByIdentity.find(socketKey) == Ring::closingSerialByIdentity.end());

  clearRingCloseTrackingState();
}

static void testTrackedCloseCompletionSkipsRecycledPointerAfterGenerationRepublish(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 9;
  Ring::publishSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(6));

  const uint64_t userData = Ring::issueCloseTracking(socketKey, 23, 6, stream.ioGeneration);

  // A recycled allocation can restart from a lower/default generation while
  // retaining the same identity address. Republish that fresh generation before
  // the first recv/send arm so stale close CQEs cannot match the old transport.
  stream.ioGeneration = 1;
  Ring::publishSocketGeneration(&stream);

  Ring::CloseCompletionTracking tracking = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedCloseCompletion(userData, tracking));
  EXPECT_EQ(suite, tracking.serial, uint64_t(6));
  EXPECT_EQ(suite, tracking.generation, uint8_t(9));
  EXPECT_FALSE(suite, Ring::shouldDispatchTrackedCloseCompletion(socketKey, tracking.serial, tracking.generation));
  EXPECT_TRUE(suite, Ring::isClosing.contains(socketKey) == false);
  EXPECT_TRUE(suite, Ring::closingSerialByIdentity.find(socketKey) == Ring::closingSerialByIdentity.end());

  clearRingCloseTrackingState();
}

static void testTrackedCloseCompletionSkipsSupersededSerialAfterGenerationWrap(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 7;
  Ring::noteSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(12));

  const uint64_t staleUserData = Ring::issueCloseTracking(socketKey, 11, 11, stream.ioGeneration);
  const uint64_t currentUserData = Ring::issueCloseTracking(socketKey, 13, 12, stream.ioGeneration);

  Ring::CloseCompletionTracking stale = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedCloseCompletion(staleUserData, stale));
  EXPECT_EQ(suite, stale.slot, 11);
  EXPECT_EQ(suite, stale.generation, uint8_t(7));
  EXPECT_FALSE(suite, Ring::shouldDispatchTrackedCloseCompletion(socketKey, stale.serial, stale.generation));
  EXPECT_TRUE(suite, Ring::isClosing.contains(socketKey));
  EXPECT_EQ(suite, Ring::closingSerialByIdentity.find(socketKey)->second, uint64_t(12));

  Ring::CloseCompletionTracking current = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedCloseCompletion(currentUserData, current));
  EXPECT_EQ(suite, current.slot, 13);
  EXPECT_TRUE(suite, Ring::shouldDispatchTrackedCloseCompletion(socketKey, current.serial, current.generation));
  EXPECT_TRUE(suite, Ring::isClosing.contains(socketKey) == false);
  EXPECT_TRUE(suite, Ring::closingSerialByIdentity.find(socketKey) == Ring::closingSerialByIdentity.end());

  clearRingCloseTrackingState();
}

static void testTrackedCloseCompletionDispatchesCurrentGeneration(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 52;
  Ring::noteSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(8));

  EXPECT_TRUE(suite, Ring::shouldDispatchTrackedCloseCompletion(socketKey, uint64_t(8), uint8_t(52)));
  EXPECT_TRUE(suite, Ring::isClosing.contains(socketKey) == false);
  EXPECT_TRUE(suite, Ring::closingSerialByIdentity.find(socketKey) == Ring::closingSerialByIdentity.end());

  clearRingCloseTrackingState();
}

static void testTrackedCloseCompletionIgnoresRetiredDuplicate(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 19;
  Ring::noteSocketGeneration(&stream);
  Ring::isClosing.insert(socketKey);
  Ring::closingSerialByIdentity.insert_or_assign(socketKey, uint64_t(3));

  const uint64_t userData = Ring::issueCloseTracking(socketKey, 41, 3, stream.ioGeneration);
  Ring::CloseCompletionTracking tracking = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedCloseCompletion(userData, tracking));
  EXPECT_TRUE(suite, Ring::retiredCloseTrackingUserData.contains(userData));
  EXPECT_FALSE(suite, Ring::resolveTrackedCloseCompletion(userData, tracking));

  clearRingCloseTrackingState();
}

static void testTrackedLinkTimeoutIgnoresRetiredDuplicate(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 17;
  Ring::noteSocketGeneration(&stream);

  const uint64_t userData = Ring::issueLinkTimeoutTracking(socketKey, stream.ioGeneration, Ring::Operation::recv);
  Ring::LinkTimeoutTracking tracking = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedLinkTimeout(userData, tracking));
  EXPECT_TRUE(suite, tracking.socket == socketKey);
  EXPECT_EQ(suite, tracking.generation, uint8_t(17));
  EXPECT_TRUE(suite, tracking.linkedOp == Ring::Operation::recv);
  EXPECT_TRUE(suite, Ring::retiredLinkTimeoutTrackingUserData.contains(userData));
  EXPECT_FALSE(suite, Ring::resolveTrackedLinkTimeout(userData, tracking));

  clearRingCloseTrackingState();
}

static void testTrackedLinkTimeoutSkipsRecycledPointerAfterGenerationRepublish(TestSuite& suite)
{
  clearRingCloseTrackingState();

  UnixStream stream;
  void *socketKey = Ring::socketIdentity(&stream);
  stream.ioGeneration = 9;
  Ring::publishSocketGeneration(&stream);

  const uint64_t userData = Ring::issueLinkTimeoutTracking(socketKey, stream.ioGeneration, Ring::Operation::recv);

  stream.ioGeneration = 1;
  Ring::publishSocketGeneration(&stream);

  Ring::LinkTimeoutTracking tracking = {};
  EXPECT_TRUE(suite, Ring::resolveTrackedLinkTimeout(userData, tracking));
  EXPECT_EQ(suite, tracking.generation, uint8_t(9));
  EXPECT_FALSE(suite, Ring::socketGenerationMatches(socketKey, tracking.generation));

  clearRingCloseTrackingState();
}

static void testMissingMsghdrCompletionIsIgnored(TestSuite& suite)
{
  Ring::msghdrPackagePool.initialize(4);

  Ring::MsghdrPackage *package = Ring::msghdrPackagePool.get();
  EXPECT_TRUE(suite, package != nullptr);
  EXPECT_TRUE(suite, Ring::msghdrPackagePool.contains(package));
  EXPECT_FALSE(suite, Ring::shouldIgnoreMissingMsghdrCompletion(package));
  EXPECT_TRUE(suite, Ring::shouldIgnoreMissingMsghdrCompletion(nullptr));

  Ring::msghdrPackagePool.relinquish(package);

  EXPECT_FALSE(suite, Ring::msghdrPackagePool.contains(package));
  EXPECT_TRUE(suite, Ring::shouldIgnoreMissingMsghdrCompletion(package));
}

static void testKeepaliveTimeoutClampsTcpUserTimeoutFloor(TestSuite& suite)
{
  TCPSocket socket;
  socket.setIPVersion(AF_INET);
  socket.createSocket();
  socket.setKeepaliveTimeoutSeconds(6);

  unsigned int userTimeoutMs = 0;
  socklen_t userTimeoutLen = sizeof(userTimeoutMs);
  int result = getsockopt(socket.fd, SOL_TCP, TCP_USER_TIMEOUT, &userTimeoutMs, &userTimeoutLen);
  EXPECT_EQ(suite, result, 0);
  EXPECT_EQ(suite, userTimeoutLen, socklen_t(sizeof(userTimeoutMs)));
  EXPECT_TRUE(suite, userTimeoutMs >= 30000u);

  socket.close();
}

struct FixedFileSlotFixture
{
  explicit FixedFileSlotFixture(uint32_t capacity = 512, uint32_t reserveLimit = 256)
      : previousFixedFiles(Ring::fixedfiles),
        previousCapacity(Ring::fixedFileCapacity),
        previousReserveLimit(Ring::fixedFileReserveLimit),
        previousRegistered(Ring::fixedFilesWereRegistered),
        previousVacantReserved(std::move(Ring::vacantFixedFileSlots)),
        previousVacantAccepted(std::move(Ring::vacantAcceptedFixedFileSlots))
  {
    Ring::fixedfiles = new int[capacity];
    Ring::fixedFileCapacity = capacity;
    Ring::fixedFileReserveLimit = reserveLimit;
    Ring::fixedFilesWereRegistered = false;
    memset(Ring::fixedfiles, 0xff, sizeof(int) * capacity);

    Ring::vacantFixedFileSlots.clear();
    Ring::vacantAcceptedFixedFileSlots.clear();

    for (uint32_t index = 1; index < reserveLimit; ++index)
    {
      Ring::vacantFixedFileSlots.insert(int(index));
    }

    for (uint32_t index = reserveLimit; index < capacity; ++index)
    {
      Ring::vacantAcceptedFixedFileSlots.insert(int(index));
    }
  }

  ~FixedFileSlotFixture()
  {
    delete[] Ring::fixedfiles;
    Ring::fixedfiles = previousFixedFiles;
    Ring::fixedFileCapacity = previousCapacity;
    Ring::fixedFileReserveLimit = previousReserveLimit;
    Ring::fixedFilesWereRegistered = previousRegistered;
    Ring::vacantFixedFileSlots = std::move(previousVacantReserved);
    Ring::vacantAcceptedFixedFileSlots = std::move(previousVacantAccepted);
  }

  int *previousFixedFiles = nullptr;
  uint32_t previousCapacity = 0;
  uint32_t previousReserveLimit = 0;
  bool previousRegistered = false;
  bytell_hash_set<int> previousVacantReserved = {};
  bytell_hash_set<int> previousVacantAccepted = {};
};

static void testFreshProcessFdAliasDoesNotUninstallOccupiedReservedSlot(TestSuite& suite)
{
  FixedFileSlotFixture fixture;

  Ring::vacantFixedFileSlots.erase(177);
  Ring::fixedfiles[177] = 41;

  UnixStream stream;
  stream.setUnixPairHalf(177);
  stream.isFixedFile = false;

  EXPECT_TRUE(suite, Ring::tryInstallFDIntoFixedFileSlot(&stream));
  EXPECT_TRUE(suite, stream.isFixedFile);
  EXPECT_TRUE(suite, stream.fslot > 0);
  EXPECT_TRUE(suite, stream.fslot != 177);
  EXPECT_EQ(suite, Ring::fixedfiles[177], 41);
  EXPECT_EQ(suite, Ring::getFDFromFixedFileSlot(stream.fslot), 177);
}

static void testQueueRecvGrowsFullBufferBeforeArming(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = (Ring::getRingFD() > 0);
  }

  EXPECT_TRUE(suite, Ring::getRingFD() > 0);
  if (Ring::getRingFD() <= 0)
  {
    return;
  }

  int fds[2] = {-1, -1};
  const bool pairCreated = (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) == 0);
  EXPECT_TRUE(suite, pairCreated);
  if (pairCreated)
  {
    UnixStream stream;
    stream.setUnixPairHalf(fds[0]);
    stream.rBuffer.reserve(16);
    std::memset(stream.rBuffer.pTail(), 0xAB, size_t(stream.rBuffer.remainingCapacity()));
    stream.rBuffer.advance(stream.rBuffer.remainingCapacity());

    const uint64_t capacityBefore = stream.rBuffer.tentativeCapacity();
    EXPECT_EQ(suite, stream.rBuffer.remainingCapacity(), uint64_t(0));

    Ring::queueRecv(&stream);

    EXPECT_TRUE(suite, stream.pendingRecv);
    EXPECT_TRUE(suite, stream.rBuffer.remainingCapacity() > 0);
    EXPECT_TRUE(suite, stream.rBuffer.tentativeCapacity() > capacityBefore);

    close(fds[0]);
    close(fds[1]);
  }

  if (createdRing)
  {
    Ring::shutdownForExec();
  }
}

} // namespace

int main()
{
  TestSuite suite;
  testPoolReuseAndOutstandingTracking(suite);
  testMemoryPoolsReuseBuffers(suite);
  testTimerWheelSchedulingAndCancellation(suite);
  testRingDispatcherRoutesHandlers(suite);
  testRingDispatcherIsThreadLocal(suite);
  testFallbackDispatcherInitDoesNotClobberLiveDispatcher(suite);
  testCoroutineStackScheduling(suite);
  testResolveTrackedCloseCompletionReturnsTracking(suite);
  testTrackedCloseCompletionSkipsReusedGeneration(suite);
  testTrackedCloseCompletionSkipsRecycledPointerAfterGenerationRepublish(suite);
  testTrackedCloseCompletionSkipsSupersededSerialAfterGenerationWrap(suite);
  testTrackedCloseCompletionDispatchesCurrentGeneration(suite);
  testTrackedCloseCompletionIgnoresRetiredDuplicate(suite);
  testTrackedLinkTimeoutIgnoresRetiredDuplicate(suite);
  testTrackedLinkTimeoutSkipsRecycledPointerAfterGenerationRepublish(suite);
  testMissingMsghdrCompletionIsIgnored(suite);
  testKeepaliveTimeoutClampsTcpUserTimeoutFloor(suite);
  testFreshProcessFdAliasDoesNotUninstallOccupiedReservedSlot(suite);
  testQueueRecvGrowsFullBufferBeforeArming(suite);
  return suite.finish("networking_support_structures_tests");
}
