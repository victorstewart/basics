// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <atomic>
#include <bitset>
#include <sched.h>
#include <thread>

#include "services/crypto.h"
#include "services/time.h"
#include "services/numbers.h"
#include "services/bytes.h"
#include "types/types.containers.h"
#include "services/threads.h"

namespace {

static int firstAllowedCore()
{
  cpu_set_t cpuSet;
  CPU_ZERO(&cpuSet);
  if (sched_getaffinity(0, sizeof(cpuSet), &cpuSet) != 0)
  {
    return -1;
  }

  for (int core = 0; core < CPU_SETSIZE; ++core)
  {
    if (CPU_ISSET(core, &cpuSet))
    {
      return core;
    }
  }

  return -1;
}

static void testRandomAndCryptoHelpers(TestSuite& suite)
{
  uint8_t zeroBitValue = Random::generateNumberWithNBits<0, uint8_t>();
  EXPECT_EQ(suite, zeroBitValue, uint8_t(0));

  for (int iteration = 0; iteration < 64; ++iteration)
  {
    uint8_t oneBitValue = Random::generateNumberWithNBits<1, uint8_t>();
    EXPECT_EQ(suite, oneBitValue, uint8_t(1));

    uint8_t bounded = Random::generateNumberWithNBits<5, uint8_t>();
    EXPECT_TRUE(suite, bounded >= 1);
    EXPECT_TRUE(suite, bounded < 32);

    uint8_t inclusive = Random::generateNumberWithNBits<5, uint8_t>(true);
    EXPECT_TRUE(suite, inclusive < 32);
  }

  String random = Crypto::randomString(64);
  EXPECT_EQ(suite, random.size(), size_t(64));
  for (char c : stringViewOf(random))
  {
    EXPECT_TRUE(suite, std::isalnum(static_cast<unsigned char>(c)) != 0);
  }

  String empty = Crypto::randomString(0);
  EXPECT_EQ(suite, empty.size(), size_t(0));

  String code = Crypto::random6DigitNumberString();
  EXPECT_EQ(suite, code.size(), size_t(6));
  for (char c : stringViewOf(code))
  {
    EXPECT_TRUE(suite, c >= '0' && c <= '9');
  }

  String password("hunter2");
  String salt("pepper");
  String hashA = Crypto::saltAndHash(password, salt);
  String hashB = Crypto::saltAndHash(password.data(), static_cast<uint32_t>(password.size()), salt);
  String hashDifferentSalt = Crypto::saltAndHash(password, String("paprika"));

  EXPECT_EQ(suite, hashA.size(), size_t(32));
  EXPECT_STRING_EQ(suite, hashA, hashB);
  EXPECT_FALSE(suite, hashA.equals(hashDifferentSalt));
}

static void testTimeHelpers(TestSuite& suite)
{
  EXPECT_EQ(suite, Time::daysToMs(2), int64_t(172800000));
  EXPECT_EQ(suite, Time::minsToMs(3), int64_t(180000));
  EXPECT_EQ(suite, Time::secToMs(4), int64_t(4000));
  EXPECT_EQ(suite, Time::secToUs(5), int64_t(5000000));
  EXPECT_EQ(suite, Time::secToNs(6), int64_t(6000000000LL));
  EXPECT_EQ(suite, Time::nsToSec(7000000000LL), int64_t(7));
  EXPECT_EQ(suite, Time::nsToMs(8000000), int64_t(8));
  EXPECT_EQ(suite, Time::nsToUs(9000), int64_t(9));
  EXPECT_EQ(suite, Time::msToNs(10), int64_t(10000000));

  struct timespec realtime = {};
  clock_gettime(CLOCK_REALTIME, &realtime);
  int64_t nowMs = Time::now<TimeResolution::ms>();
  EXPECT_TRUE(suite, std::llabs(nowMs - Time::timespecToMs(realtime)) < 1000);

  struct timespec boottime = {};
  clock_gettime(CLOCK_BOOTTIME, &boottime);
  EXPECT_TRUE(suite, std::llabs(Time::msSinceBoot() - Time::timespecToMs(boottime)) < 1000);

  auto epoch = msSinceEpochToYearMonthDay(0);
  EXPECT_EQ(suite, int(epoch.year()), 1970);
  EXPECT_EQ(suite, unsigned(epoch.month()), 1u);
  EXPECT_EQ(suite, unsigned(epoch.day()), 1u);
}

static uint8_t expectedAlignment(uint8_t *pointer)
{
  uintptr_t value = reinterpret_cast<uintptr_t>(pointer);

  if ((value % 16) == 0)
  {
    return 16;
  }
  if ((value % 8) == 0)
  {
    return 8;
  }
  if ((value % 4) == 0)
  {
    return 4;
  }
  if ((value % 2) == 0)
  {
    return 2;
  }

  return 1;
}

static void testMemoryHelpers(TestSuite& suite)
{
  alignas(16) uint8_t buffer[64] {};

  uint8_t *unalignedEight = buffer + 1;
  uintptr_t originalEight = reinterpret_cast<uintptr_t>(unalignedEight);
  uintptr_t expectedEight = originalEight + ((-originalEight) & (uint64_t(Alignment::eight) - 1));
  align<Alignment::eight>(unalignedEight);
  EXPECT_EQ(suite, reinterpret_cast<uintptr_t>(unalignedEight), expectedEight);
  EXPECT_EQ(suite, reinterpret_cast<uintptr_t>(unalignedEight) % 8, uintptr_t(0));

  uint8_t *unalignedFour = buffer + 3;
  uintptr_t originalFour = reinterpret_cast<uintptr_t>(unalignedFour);
  uintptr_t expectedFour = originalFour + ((-originalFour) & (uint64_t(Alignment::four) - 1));
  align(Alignment::four, unalignedFour);
  EXPECT_EQ(suite, reinterpret_cast<uintptr_t>(unalignedFour), expectedFour);
  EXPECT_EQ(suite, reinterpret_cast<uintptr_t>(unalignedFour) % 4, uintptr_t(0));

  EXPECT_EQ(suite, alignmentOfAddress(buffer), expectedAlignment(buffer));
  EXPECT_EQ(suite, alignmentOfAddress(buffer + 1), expectedAlignment(buffer + 1));

  EXPECT_EQ(suite, shiftRequiredToAlign(8, 0), uint8_t(0));
  EXPECT_EQ(suite, shiftRequiredToAlign(8, 1), uint8_t(7));
  EXPECT_EQ(suite, shiftRequiredToAlign(8, 7), uint8_t(1));
  EXPECT_EQ(suite, shiftRequiredToAlign(8, 8), uint8_t(0));
  EXPECT_EQ(suite, shiftRequiredToAlign(8, 12), uint8_t(4));
}

static void testNumbersBytesAndHash(TestSuite& suite)
{
  std::bitset<128> bits;
  bits.set(0);
  bits.set(63);
  bits.set(64);
  bits.set(127);

  uint128_t value = bitsetToU128(bits);
  std::bitset<128> roundTrip = u128ToBitset(value);
  EXPECT_TRUE(suite, roundTrip == bits);
  EXPECT_TRUE(suite, roundTrip[0]);
  EXPECT_TRUE(suite, roundTrip[63]);
  EXPECT_TRUE(suite, roundTrip[64]);
  EXPECT_TRUE(suite, roundTrip[127]);
  EXPECT_FALSE(suite, roundTrip[62]);
  EXPECT_FALSE(suite, roundTrip[65]);

  std::bitset<128> zeroBits;
  EXPECT_TRUE(suite, u128ToBitset(bitsetToU128(zeroBits)) == zeroBits);

  std::bitset<128> allBits;
  allBits.set();
  EXPECT_TRUE(suite, u128ToBitset(bitsetToU128(allBits)) == allBits);

  EXPECT_EQ(suite, Bytes::MBtoB(4), uint64_t(4 * 1024 * 1024));
  EXPECT_EQ(suite, Bytes::BtoMB(7 * 1024 * 1024), uint64_t(7));
  EXPECT_EQ(suite, Bytes::BtoMB((7 * 1024 * 1024) + 12345), uint64_t(7));

  uint8_t bytes[] = {1, 2, 3, 4};
  uint8_t copy[] = {1, 2, 3, 4};
  EXPECT_EQ(suite, Hasher::hash<Hasher::SeedPolicy::thread_shared>(bytes, sizeof(bytes)), Hasher::hash<Hasher::SeedPolicy::thread_shared>(copy, sizeof(copy)));
  EXPECT_EQ(suite, Hasher::hash(bytes, sizeof(bytes), 123), Hasher::hash(copy, sizeof(copy), 123));

  uint8_t empty = 0;
  EXPECT_EQ(suite, Hasher::hash<Hasher::SeedPolicy::thread_shared>(&empty, 0), Hasher::hash<Hasher::SeedPolicy::thread_shared>(&empty, 0));

  const int64_t originalGlobalSeed = Hasher::globalSeed();
  const int64_t originalThreadSeed = Hasher::threadSeed();

  Hasher::setGlobalSeed(101);
  uint64_t globalHashA = Hasher::hash<Hasher::SeedPolicy::global_shared>(bytes, sizeof(bytes));
  uint64_t globalHashB = Hasher::hash<Hasher::SeedPolicy::global_shared>(copy, sizeof(copy));
  EXPECT_EQ(suite, globalHashA, globalHashB);

  Hasher::setGlobalSeed(202);
  uint64_t globalHashC = Hasher::hash<Hasher::SeedPolicy::global_shared>(bytes, sizeof(bytes));
  EXPECT_TRUE(suite, globalHashA != globalHashC);

  Hasher::setThreadSeed(303);
  uint64_t threadHashA = Hasher::hash<Hasher::SeedPolicy::thread_shared>(bytes, sizeof(bytes));
  uint64_t threadHashB = Hasher::hash<Hasher::SeedPolicy::thread_shared>(copy, sizeof(copy));
  EXPECT_EQ(suite, threadHashA, threadHashB);
  EXPECT_EQ(suite, threadHashA, Hasher::hash(bytes, sizeof(bytes), 303));

  (void)Hasher::hash<Hasher::SeedPolicy::per_hash_random>(bytes, sizeof(bytes));

  Hasher::setGlobalSeed(originalGlobalSeed);
  Hasher::setThreadSeed(originalThreadSeed);
}

static void testThreadHelpers(TestSuite& suite)
{
  int core = firstAllowedCore();
  EXPECT_TRUE(suite, core >= 0);
  if (core < 0)
  {
    return;
  }

  Thread::pinThisThreadToCore(core);

  cpu_set_t cpuSet;
  CPU_ZERO(&cpuSet);
  EXPECT_EQ(suite, sched_getaffinity(0, sizeof(cpuSet), &cpuSet), 0);
  EXPECT_TRUE(suite, CPU_ISSET(core, &cpuSet));

  std::atomic<bool> ran = false;
  Thread::startDetachedOnCore(core, [&]() -> void {
    ran.store(true, std::memory_order_release);
  });

  for (int attempt = 0; attempt < 100 && !ran.load(std::memory_order_acquire); ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  EXPECT_TRUE(suite, ran.load(std::memory_order_acquire));
}

} // namespace

int main()
{
  TestSuite suite;

  testRandomAndCryptoHelpers(suite);
  testTimeHelpers(suite);
  testMemoryHelpers(suite);
  testNumbersBytesAndHash(suite);
  testThreadHelpers(suite);

  return suite.finish("services sanity tests");
}
