// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cstdint>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <utility>
#include <vector>

#include "macros/time.h"
#include "types/types.containers.h"
#include "networking/pool.h"
#include "networking/timerwheel.h"
#include "networking/coroutinestack.h"

struct io_uring_recvmsg_out;

class TimeoutPacket;

class TimeoutDispatcher {
public:
  virtual ~TimeoutDispatcher() = default;
  virtual void dispatchTimeout(TimeoutPacket *packet) = 0;
};

class TimeoutPacket {
public:
  void *originator = nullptr;
  TimeoutDispatcher *dispatcher = nullptr;
};

class RingLifecycle {
public:
  virtual ~RingLifecycle() = default;
  virtual void beforeRing(void) {}
  virtual void afterRing(void) {}
  virtual bool signalHandler(const struct signalfd_siginfo&)
  {
    return true;
  }
};

class RingInterface {
public:
  virtual ~RingInterface() = default;
  virtual void waitidHandler(void *) {}
  virtual void timeoutHandler(TimeoutPacket *, int) {}
  virtual void acceptHandler(void *, int) {}
  virtual void acceptMultishotHandler(void *, int, bool) {}
  virtual void closeHandler(void *) {}
  virtual void connectHandler(void *, int) {}
  virtual void tcpFastOpenHandler(void *, int) {}
  virtual void recvHandler(void *, int) {}
  virtual void recvmsgHandler(void *, struct msghdr *, int) {}
  virtual void recvmsgMultishotHandler(void *, struct io_uring_recvmsg_out *, int, bool) {}
  virtual void sendHandler(void *, int) {}
  virtual void sendmsgHandler(void *, struct msghdr *, int) {}
  virtual void shutdownHandler(void *) {}
  virtual void pollHandler(void *, int) {}
  virtual void restartMultishotRecvMsgOn(void *) {}
};

class Ring {
public:
  static inline RingInterface *interfacer = nullptr;
  static inline RingLifecycle *lifecycler = nullptr;
};

#include "networking/multiplexer.h"

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
        savedInterfacer(Ring::interfacer),
        savedLifecycler(Ring::lifecycler)
  {
  }

  ~DispatcherScope()
  {
    RingDispatcher::dispatcher = savedDispatcher;
    Ring::interfacer = savedInterfacer;
    Ring::lifecycler = savedLifecycler;
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
  EXPECT_TRUE(suite, Ring::interfacer == &scope.localDispatcher);
  EXPECT_TRUE(suite, Ring::lifecycler == &scope.localDispatcher);

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

} // namespace

int main()
{
  TestSuite suite;
  testPoolReuseAndOutstandingTracking(suite);
  testMemoryPoolsReuseBuffers(suite);
  testTimerWheelSchedulingAndCancellation(suite);
  testRingDispatcherRoutesHandlers(suite);
  testCoroutineStackScheduling(suite);
  return suite.finish("networking_support_structures_tests");
}
