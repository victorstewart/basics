// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"
#include "tests/tls_support.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "services/base64.h"
#include "services/base62.h"
#include "services/bitsery.h"
#include "services/crypto.h"
#include "services/filesystem.h"
#include "services/numbers.h"
#include "types/types.containers.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/message.h"
#include "networking/socket.h"
#include "networking/stream.h"
#include "networking/tls.h"

namespace fs = std::filesystem;

namespace {

using tls_test_support::freeCtx;
using tls_test_support::makeDeterministicPayload;
using tls_test_support::negotiateTLS;
using tls_test_support::pumpTLS;
using tls_test_support::readPeerMaterial;
using tls_test_support::TLSMaterial;

volatile uint64_t g_benchmark_sink = 0;
constexpr int64_t kBenchmarkHasherSeed = 0x123456789abcdef0LL;
constexpr Hasher::SeedPolicy kBenchmarkHasherSeedPolicy = Hasher::SeedPolicy::global_shared;

template <typename Key, typename Value>
using BenchmarkHashMap = bytell_hash_map_with_policy<Key, Value, kBenchmarkHasherSeedPolicy>;

template <typename Value>
using BenchmarkHashSet = bytell_hash_set_with_policy<Value, kBenchmarkHasherSeedPolicy>;

class DeterministicRng {
private:

  uint64_t state_;

public:

  explicit DeterministicRng(uint64_t seed)
      : state_(seed)
  {}

  uint64_t next()
  {
    uint64_t x = state_;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state_ = x;
    return x;
  }

  uint8_t nextByte()
  {
    return static_cast<uint8_t>(next());
  }
};

static void benchmarkConsume(uint64_t value)
{
  g_benchmark_sink ^= value + 0x9e3779b97f4a7c15ULL;
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

static void benchmarkConsumeString(const String& value)
{
  uint64_t sample = value.size();
  if (value.size() > 0)
  {
    sample ^= uint64_t(value.data()[0]) << 8;
    sample ^= uint64_t(value.data()[value.size() / 2]) << 16;
    sample ^= uint64_t(value.data()[value.size() - 1]) << 24;
  }
  benchmarkConsume(sample);
}

static std::vector<uint8_t> makeRandomBytes(size_t length, uint64_t seed)
{
  DeterministicRng rng(seed);
  std::vector<uint8_t> bytes(length);

  for (uint8_t& byte : bytes)
  {
    byte = rng.nextByte();
  }

  return bytes;
}

static std::vector<uint64_t> makeIntegralKeys(size_t count, uint64_t seed)
{
  DeterministicRng rng(seed);
  std::vector<uint64_t> keys;
  keys.reserve(count);

  for (size_t index = 0; index < count; ++index)
  {
    keys.push_back(rng.next());
  }

  return keys;
}

static size_t roundUpToPageSize(size_t bytes)
{
  long pageSize = ::sysconf(_SC_PAGESIZE);
  if (pageSize <= 0)
  {
    pageSize = 4096;
  }

  size_t page = static_cast<size_t>(pageSize);
  size_t remainder = bytes % page;
  return remainder == 0 ? bytes : (bytes + (page - remainder));
}

static uint64_t *mapStablePointerStorage(size_t count, size_t& mappedBytes)
{
  mappedBytes = roundUpToPageSize(count * sizeof(uint64_t));
#ifdef MAP_FIXED_NOREPLACE
  constexpr std::uintptr_t kPointerStorageCandidates[] = {
      0x5f1000000000ULL,
      0x5f2000000000ULL,
      0x5f3000000000ULL,
  };

  for (std::uintptr_t candidate : kPointerStorageCandidates)
  {
    void *mapping = ::mmap(
        reinterpret_cast<void *>(candidate),
        mappedBytes,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0);
    if (mapping != MAP_FAILED)
    {
      return static_cast<uint64_t *>(mapping);
    }
  }
#endif

  void *mapping = ::mmap(nullptr, mappedBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED)
  {
    throw std::runtime_error("failed to map pointer benchmark storage");
  }

  return static_cast<uint64_t *>(mapping);
}

static String makeRepeatedValue(const std::string_view prefix, size_t index, size_t payloadBytes)
{
  std::string text(prefix);
  text += '-';
  text += std::to_string(index);
  while (text.size() < payloadBytes)
  {
    text.push_back(char('a' + (text.size() % 26)));
  }

  String value;
  value.assign(std::string_view(text));
  return value;
}

static std::vector<String> makeStringKeys(size_t count, size_t payloadBytes)
{
  std::vector<String> keys;
  keys.reserve(count);

  for (size_t index = 0; index < count; ++index)
  {
    keys.push_back(makeRepeatedValue("key", index, payloadBytes));
  }

  return keys;
}

static BenchmarkHashMap<int, String> makeStringMapPayload(size_t entryCount, size_t valueBytes)
{
  BenchmarkHashMap<int, String> payload;
  payload.reserve(entryCount);

  for (size_t index = 0; index < entryCount; ++index)
  {
    payload.insert_or_assign(int(index), makeRepeatedValue("value", index, valueBytes));
  }

  return payload;
}

template <typename Key>
struct LookupFixture {

  BenchmarkHashMap<Key, uint64_t> map;
  std::vector<Key> queries;
};

template <typename Key>
static LookupFixture<Key> makeLookupFixture(const std::vector<Key>& keys, size_t queryCount)
{
  LookupFixture<Key> fixture;
  fixture.map.reserve(keys.size());
  fixture.queries.reserve(std::min(queryCount, keys.size()));

  for (size_t index = 0; index < keys.size(); ++index)
  {
    fixture.map.insert_or_assign(keys[index], uint64_t(index * 7));
    if (index < queryCount)
    {
      fixture.queries.push_back(keys[index]);
    }
  }

  return fixture;
}

template <typename Key>
static uint64_t runHasherBatch(const std::vector<Key>& keys, uint64_t iterations, uint64_t hashesPerIteration)
{
  noncrypto_hasher_with_policy<kBenchmarkHasherSeedPolicy> hasher;
  uint64_t sum = 0;
  size_t cursor = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    for (uint64_t hashIndex = 0; hashIndex < hashesPerIteration; ++hashIndex)
    {
      sum += uint64_t(hasher(keys[cursor]));
      cursor = (cursor + 1) % keys.size();
    }
  }

  return sum;
}

template <typename Key>
static uint64_t runEqualityBatch(const std::vector<Key>& keys, uint64_t iterations, uint64_t comparisonsPerIteration)
{
  keys_are_equal equal;
  uint64_t matches = 0;
  size_t cursor = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    for (uint64_t comparisonIndex = 0; comparisonIndex < comparisonsPerIteration; ++comparisonIndex)
    {
      const Key& lhs = keys[cursor];
      const Key& rhs = keys[(cursor + 1) % keys.size()];

      matches += uint64_t(equal(lhs, lhs));
      matches += uint64_t(equal(lhs, rhs));
      cursor = (cursor + 1) % keys.size();
    }
  }

  return matches;
}

template <typename Key>
static uint64_t runLookupBatch(const LookupFixture<Key>& fixture, uint64_t iterations, uint64_t lookupsPerIteration)
{
  uint64_t sum = 0;
  size_t cursor = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    for (uint64_t lookup = 0; lookup < lookupsPerIteration; ++lookup)
    {
      const Key& key = fixture.queries[cursor];
      auto found = fixture.map.find(key);
      if (found == fixture.map.end())
      {
        throw std::runtime_error("lookup benchmark failed to find a prepared key");
      }

      sum += found->second;
      cursor = (cursor + 1) % fixture.queries.size();
    }
  }

  return sum;
}

template <typename Key>
static uint64_t runMapLifecycleBatch(const std::vector<Key>& keys, uint64_t iterations)
{
  uint64_t sum = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    BenchmarkHashMap<Key, uint64_t> map;
    map.reserve(keys.size());

    for (size_t index = 0; index < keys.size(); ++index)
    {
      map.insert_or_assign(keys[index], uint64_t(index));
    }

    for (size_t index = 0; index < keys.size(); ++index)
    {
      auto found = map.find(keys[index]);
      if (found == map.end())
      {
        throw std::runtime_error("map lifecycle benchmark lookup failed");
      }

      sum += found->second;
    }

    for (size_t index = 0; index < keys.size(); ++index)
    {
      auto found = map.find(keys[index]);
      if (found == map.end())
      {
        throw std::runtime_error("map lifecycle benchmark erase failed");
      }

      map.erase(found);
    }

    sum += map.size();
  }

  return sum;
}

template <typename Key>
static uint64_t runSetLifecycleBatch(const std::vector<Key>& keys, uint64_t iterations)
{
  uint64_t sum = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    BenchmarkHashSet<Key> set;
    set.reserve(keys.size());

    for (const Key& key : keys)
    {
      set.insert(key);
    }

    for (const Key& key : keys)
    {
      auto found = set.find(key);
      if (found == set.end())
      {
        throw std::runtime_error("set lifecycle benchmark lookup failed");
      }

      sum += 1;
    }

    for (const Key& key : keys)
    {
      size_t erased = set.erase(key);
      if (erased != 1)
      {
        throw std::runtime_error("set lifecycle benchmark erase failed");
      }
    }

    sum += set.size();
  }

  return sum;
}

template <typename Value>
static uint64_t runVectorLifecycleBatch(const std::vector<Value>& values, uint64_t iterations)
{
  uint64_t sum = 0;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration)
  {
    Vector<Value> vector;
    vector.reserve(values.size());

    for (const Value& value : values)
    {
      vector.push_back(value);
    }

    for (size_t index = 0; index < values.size(); index += 4)
    {
      if (vector.contains(values[index]) == false)
      {
        throw std::runtime_error("vector lifecycle benchmark contains failed");
      }

      sum += uint64_t(vector[index]);
    }

    for (size_t index = 0; index < values.size(); index += 4)
    {
      vector.erase(values[index]);
    }

    sum += vector.size();
  }

  return sum;
}

static const char *benchmarkAllocatorMode(void)
{
#if USE_MIMALLOC == 0
  return "none";
#elif USE_MIMALLOC == 1
  return "object";
#else
  return "explicit";
#endif
}

struct BenchmarkOptions {

  bool listOnly = false;
  std::string exact;
  std::string filter;
  uint64_t minTimeMs = 50;
  uint64_t forcedIterations = 0;
  uint32_t warmupRuns = 0;
  uint32_t repetitions = 5;
};

struct BenchmarkDefinition {

  std::string name;
  std::string description;
  uint64_t operationsPerIteration = 1;
  uint64_t bytesPerIteration = 0;
  std::function<void(uint64_t)> run;
};

static void printUsage(const char *argv0)
{
  std::cerr
      << "Usage:\n"
      << "  " << argv0 << " --list\n"
      << "  " << argv0 << " [--exact name] [--filter substring] [--min-time-ms n] [--iterations n] [--warmup-runs n] [--repetitions n]\n\n"
      << "Options:\n"
      << "  --list             List benchmark names and descriptions.\n"
      << "  --exact value      Run only the benchmark whose name exactly matches value.\n"
      << "  --filter value     Run only benchmarks whose name contains value.\n"
      << "  --min-time-ms n    Minimum timed duration used for calibration per benchmark. Default: 50.\n"
      << "  --iterations n     Override calibrated iterations with a fixed iteration count.\n"
      << "  --warmup-runs n    Untimed warm-up executions after calibration. Default: 0.\n"
      << "  --repetitions n    Number of timed repetitions per benchmark. Default: 5.\n";
}

static uint64_t parseUnsignedArgument(const char *flag, const char *value)
{
  if (value == nullptr || value[0] == '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires a non-empty numeric value");
  }

  char *terminal = nullptr;
  unsigned long long parsed = std::strtoull(value, &terminal, 10);
  if (terminal == value || terminal == nullptr || *terminal != '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires a numeric value");
  }

  return static_cast<uint64_t>(parsed);
}

static BenchmarkOptions parseOptions(int argc, char **argv)
{
  BenchmarkOptions options;

  for (int index = 1; index < argc; ++index)
  {
    std::string_view argument(argv[index]);
    if (argument == "--list")
    {
      options.listOnly = true;
    }
    else if (argument == "--exact")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--exact requires a value");
      }
      options.exact = argv[++index];
    }
    else if (argument == "--filter")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--filter requires a value");
      }
      options.filter = argv[++index];
    }
    else if (argument == "--min-time-ms")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--min-time-ms requires a value");
      }
      options.minTimeMs = parseUnsignedArgument("--min-time-ms", argv[++index]);
      if (options.minTimeMs == 0)
      {
        throw std::runtime_error("--min-time-ms must be greater than 0");
      }
    }
    else if (argument == "--iterations")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--iterations requires a value");
      }

      options.forcedIterations = parseUnsignedArgument("--iterations", argv[++index]);
      if (options.forcedIterations == 0)
      {
        throw std::runtime_error("--iterations must be greater than 0");
      }
    }
    else if (argument == "--warmup-runs")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--warmup-runs requires a value");
      }
      options.warmupRuns = static_cast<uint32_t>(parseUnsignedArgument("--warmup-runs", argv[++index]));
    }
    else if (argument == "--repetitions")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--repetitions requires a value");
      }
      options.repetitions = static_cast<uint32_t>(parseUnsignedArgument("--repetitions", argv[++index]));
      if (options.repetitions == 0)
      {
        throw std::runtime_error("--repetitions must be greater than 0");
      }
    }
    else if (argument == "-h" || argument == "--help")
    {
      printUsage(argv[0]);
      std::exit(0);
    }
    else
    {
      throw std::runtime_error("unknown argument: " + std::string(argument));
    }
  }

  return options;
}

static bool matchesSelection(const BenchmarkDefinition& benchmark, const BenchmarkOptions& options)
{
  if (!options.exact.empty())
  {
    return benchmark.name == options.exact;
  }

  return options.filter.empty() || (benchmark.name.find(options.filter) != std::string::npos);
}

static uint64_t measureNanoseconds(const BenchmarkDefinition& benchmark, uint64_t iterations)
{
  auto start = std::chrono::steady_clock::now();
  benchmark.run(iterations);
  auto end = std::chrono::steady_clock::now();
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

static uint64_t roundUpToPowerOfTwo(uint64_t value)
{
  if (value <= 1)
  {
    return 1;
  }

  if (value > (uint64_t(1) << 63))
  {
    return std::numeric_limits<uint64_t>::max();
  }

  value -= 1;
  value |= value >> 1;
  value |= value >> 2;
  value |= value >> 4;
  value |= value >> 8;
  value |= value >> 16;
  value |= value >> 32;
  return value + 1;
}

static uint64_t scaleIterationsToTargetDuration(uint64_t iterations, uint64_t elapsedNs, uint64_t targetNs)
{
  if (elapsedNs == 0)
  {
    if (iterations > (std::numeric_limits<uint64_t>::max() / 2))
    {
      return std::numeric_limits<uint64_t>::max();
    }

    return iterations * 2;
  }

  long double scaled = std::ceil((static_cast<long double>(iterations) * static_cast<long double>(targetNs)) /
                                 static_cast<long double>(elapsedNs));
  if (scaled < 1.0L)
  {
    scaled = 1.0L;
  }

  long double maxValue = static_cast<long double>(std::numeric_limits<uint64_t>::max());
  if (scaled >= maxValue)
  {
    return std::numeric_limits<uint64_t>::max();
  }

  return roundUpToPowerOfTwo(static_cast<uint64_t>(scaled));
}

static uint64_t calibrateIterations(const BenchmarkDefinition& benchmark, uint64_t minTimeMs)
{
  const uint64_t minTimeNs = minTimeMs * 1000ULL * 1000ULL;
  uint64_t iterations = 1;
  uint64_t elapsedNs = 0;

  for (;;)
  {
    elapsedNs = measureNanoseconds(benchmark, iterations);
    if (elapsedNs >= minTimeNs)
    {
      break;
    }

    if (iterations > (std::numeric_limits<uint64_t>::max() / 2))
    {
      return iterations;
    }

    iterations *= 2;
  }

  // Refine calibration on a warmed workload so the chosen iteration count is not dominated
  // by cold cache / first-touch behavior from the exponential search.
  benchmark.run(iterations);
  uint64_t refinedElapsedNs = measureNanoseconds(benchmark, iterations);
  uint64_t refinedIterations = scaleIterationsToTargetDuration(iterations, refinedElapsedNs, minTimeNs);
  if (refinedIterations != iterations)
  {
    iterations = refinedIterations;
    benchmark.run(iterations);
    refinedElapsedNs = measureNanoseconds(benchmark, iterations);
    if (refinedElapsedNs < minTimeNs)
    {
      uint64_t finalIterations = scaleIterationsToTargetDuration(iterations, refinedElapsedNs, minTimeNs);
      if (finalIterations > iterations)
      {
        iterations = finalIterations;
      }
    }
  }

  return iterations;
}

static double medianNanoseconds(std::vector<uint64_t>& samples)
{
  std::sort(samples.begin(), samples.end());
  size_t midpoint = samples.size() / 2;
  if ((samples.size() % 2) == 1)
  {
    return static_cast<double>(samples[midpoint]);
  }

  return (static_cast<double>(samples[midpoint - 1]) + static_cast<double>(samples[midpoint])) / 2.0;
}

static void printResult(const BenchmarkDefinition& benchmark, uint64_t iterations, const std::vector<uint64_t>& samples)
{
  std::vector<uint64_t> ordered = samples;
  double medianNs = medianNanoseconds(ordered);
  uint64_t minNs = ordered.front();
  uint64_t maxNs = ordered.back();
  double operations = static_cast<double>(iterations) * static_cast<double>(benchmark.operationsPerIteration);
  double nsPerOperation = medianNs / operations;
  double opsPerSecond = (operations * 1.0e9) / medianNs;

  std::cout << std::fixed << std::setprecision(2);
  std::cout
      << "benchmark=" << benchmark.name
      << " iterations=" << iterations
      << " repetitions=" << samples.size()
      << " median_ns=" << medianNs
      << " min_ns=" << minNs
      << " max_ns=" << maxNs
      << " ns_per_op=" << nsPerOperation
      << " ops_per_s=" << opsPerSecond;

  if (benchmark.bytesPerIteration > 0)
  {
    double bytesPerRun = static_cast<double>(iterations) * static_cast<double>(benchmark.bytesPerIteration);
    double mibPerSecond = (bytesPerRun / (1024.0 * 1024.0)) / (medianNs / 1.0e9);
    std::cout << " mib_per_s=" << mibPerSecond;
  }

  std::cout << '\n';
}

static std::vector<BenchmarkDefinition> makeBenchmarks()
{
  std::vector<BenchmarkDefinition> benchmarks;

  const std::string kSmallLine = "X-Basics-Trace: 0123456789abcdef\r\n";
  constexpr uint64_t kStringLinesPerIteration = 64;
  benchmarks.push_back(BenchmarkDefinition {
      .name = "string.append.small_lines",
      .description = "Repeated short-line append workload for String growth and tail writes.",
      .operationsPerIteration = kStringLinesPerIteration,
      .bytesPerIteration = kStringLinesPerIteration * kSmallLine.size(),
      .run = [kSmallLine](uint64_t iterations) -> void {
        String builder;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          builder.clear();
          for (uint64_t line = 0; line < kStringLinesPerIteration; ++line)
          {
            builder.append(kSmallLine.data(), kSmallLine.size());
          }
          benchmarkConsumeString(builder);
        }
      }});

  constexpr size_t kContainerEntryCount = 1024;
  constexpr uint64_t kContainerOpsPerIteration = 1024;
  auto stringKeys = std::make_shared<std::vector<String>>(makeStringKeys(kContainerEntryCount, 24));
  auto integralKeys = std::make_shared<std::vector<uint64_t>>(makeIntegralKeys(kContainerEntryCount, 0xC017A1AULL));

  struct PointerKeysFixture {
    uint64_t *storage = nullptr;
    size_t mappedBytes = 0;
    std::vector<const uint64_t *> keys;

    ~PointerKeysFixture()
    {
      if (storage != nullptr)
      {
        ::munmap(storage, mappedBytes);
      }
    }
  };

  auto pointerKeys = std::make_shared<PointerKeysFixture>();
  pointerKeys->storage = mapStablePointerStorage(kContainerEntryCount, pointerKeys->mappedBytes);
  pointerKeys->keys.reserve(kContainerEntryCount);
  for (size_t index = 0; index < kContainerEntryCount; ++index)
  {
    pointerKeys->storage[index] = integralKeys->at(index);
    pointerKeys->keys.push_back(&pointerKeys->storage[index]);
  }

  auto stringLookupFixture = std::make_shared<LookupFixture<String>>(makeLookupFixture(*stringKeys, kContainerOpsPerIteration));
  auto integralLookupFixture = std::make_shared<LookupFixture<uint64_t>>(makeLookupFixture(*integralKeys, kContainerOpsPerIteration));
  auto pointerLookupFixture = std::make_shared<LookupFixture<const uint64_t *>>(makeLookupFixture(pointerKeys->keys, kContainerOpsPerIteration));

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.noncrypto_hasher.string_keys",
      .description = "Direct noncrypto_hasher throughput on String keys.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [stringKeys](uint64_t iterations) -> void {
        benchmarkConsume(runHasherBatch(*stringKeys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.noncrypto_hasher.integral_keys",
      .description = "Direct noncrypto_hasher throughput on integral keys.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [integralKeys](uint64_t iterations) -> void {
        benchmarkConsume(runHasherBatch(*integralKeys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.noncrypto_hasher.pointer_keys",
      .description = "Direct noncrypto_hasher throughput on pointer keys.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [pointerKeys](uint64_t iterations) -> void {
        benchmarkConsume(runHasherBatch(pointerKeys->keys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.keys_are_equal.string_keys",
      .description = "Direct keys_are_equal throughput on String keys with equal and unequal comparisons.",
      .operationsPerIteration = kContainerOpsPerIteration * 2,
      .bytesPerIteration = 0,
      .run = [stringKeys](uint64_t iterations) -> void {
        benchmarkConsume(runEqualityBatch(*stringKeys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.keys_are_equal.integral_keys",
      .description = "Direct keys_are_equal throughput on integral keys with equal and unequal comparisons.",
      .operationsPerIteration = kContainerOpsPerIteration * 2,
      .bytesPerIteration = 0,
      .run = [integralKeys](uint64_t iterations) -> void {
        benchmarkConsume(runEqualityBatch(*integralKeys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.keys_are_equal.pointer_keys",
      .description = "Direct keys_are_equal throughput on pointer keys with equal and unequal comparisons.",
      .operationsPerIteration = kContainerOpsPerIteration * 2,
      .bytesPerIteration = 0,
      .run = [pointerKeys](uint64_t iterations) -> void {
        benchmarkConsume(runEqualityBatch(pointerKeys->keys, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.lookup_string_keys",
      .description = "Repeated lookup batch against bytell_hash_map<String, uint64_t>.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [stringLookupFixture](uint64_t iterations) -> void {
        benchmarkConsume(runLookupBatch(*stringLookupFixture, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.lookup_integral_keys",
      .description = "Repeated lookup batch against bytell_hash_map<uint64_t, uint64_t>.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [integralLookupFixture](uint64_t iterations) -> void {
        benchmarkConsume(runLookupBatch(*integralLookupFixture, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.lookup_pointer_keys",
      .description = "Repeated lookup batch against bytell_hash_map<const uint64_t *, uint64_t>.",
      .operationsPerIteration = kContainerOpsPerIteration,
      .bytesPerIteration = 0,
      .run = [pointerLookupFixture](uint64_t iterations) -> void {
        benchmarkConsume(runLookupBatch(*pointerLookupFixture, iterations, kContainerOpsPerIteration));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.insert_lookup_erase_string_keys",
      .description = "Construct, query, and drain bytell_hash_map<String, uint64_t> per iteration.",
      .operationsPerIteration = kContainerEntryCount * 3,
      .bytesPerIteration = 0,
      .run = [stringKeys](uint64_t iterations) -> void {
        benchmarkConsume(runMapLifecycleBatch(*stringKeys, iterations));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.insert_lookup_erase_integral_keys",
      .description = "Construct, query, and drain bytell_hash_map<uint64_t, uint64_t> per iteration.",
      .operationsPerIteration = kContainerEntryCount * 3,
      .bytesPerIteration = 0,
      .run = [integralKeys](uint64_t iterations) -> void {
        benchmarkConsume(runMapLifecycleBatch(*integralKeys, iterations));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_map.insert_lookup_erase_pointer_keys",
      .description = "Construct, query, and drain bytell_hash_map<const uint64_t *, uint64_t> per iteration.",
      .operationsPerIteration = kContainerEntryCount * 3,
      .bytesPerIteration = 0,
      .run = [pointerKeys](uint64_t iterations) -> void {
        benchmarkConsume(runMapLifecycleBatch(pointerKeys->keys, iterations));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.bytell_hash_set.insert_lookup_erase_string_keys",
      .description = "Construct, query, and drain bytell_hash_set<String> per iteration.",
      .operationsPerIteration = kContainerEntryCount * 3,
      .bytesPerIteration = 0,
      .run = [stringKeys](uint64_t iterations) -> void {
        benchmarkConsume(runSetLifecycleBatch(*stringKeys, iterations));
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "containers.vector.push_contains_erase_integral_values",
      .description = "Push, contains-check, and erase integral values in the Vector wrapper.",
      .operationsPerIteration = kContainerEntryCount + (kContainerEntryCount / 4) * 2,
      .bytesPerIteration = 0,
      .run = [integralKeys](uint64_t iterations) -> void {
        benchmarkConsume(runVectorLifecycleBatch(*integralKeys, iterations));
      }});

  auto base64Input = std::make_shared<std::vector<uint8_t>>(makeRandomBytes(4096, 0xB640ULL));
  auto base64Encoded = std::make_shared<String>();
  Base64::encode(base64Input->data(), base64Input->size(), *base64Encoded);

  benchmarks.push_back(BenchmarkDefinition {
      .name = "codec.base64.encode_4k",
      .description = "Encode a deterministic 4 KiB byte buffer to Base64.",
      .operationsPerIteration = 1,
      .bytesPerIteration = base64Input->size(),
      .run = [base64Input](uint64_t iterations) -> void {
        String output;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          output.clear();
          Base64::encode(base64Input->data(), base64Input->size(), output);
          benchmarkConsumeString(output);
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "codec.base64.decode_4k",
      .description = "Decode a deterministic Base64 payload whose plaintext is 4 KiB.",
      .operationsPerIteration = 1,
      .bytesPerIteration = base64Input->size(),
      .run = [base64Encoded](uint64_t iterations) -> void {
        String output;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          output.clear();
          if (Base64::decode(base64Encoded->data(), base64Encoded->size(), output) == false)
          {
            throw std::runtime_error("Base64 decode benchmark failed");
          }
          benchmarkConsumeString(output);
        }
      }});

  auto base62Input = std::make_shared<std::vector<uint8_t>>(makeRandomBytes(255, 0xB620ULL));
  benchmarks.push_back(BenchmarkDefinition {
      .name = "codec.base62.encode_255",
      .description = "Encode the largest supported Base62 input buffer length.",
      .operationsPerIteration = 1,
      .bytesPerIteration = base62Input->size(),
      .run = [base62Input](uint64_t iterations) -> void {
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          String encoded = Base62::toBase62(base62Input->data(), static_cast<uint8_t>(base62Input->size()));
          benchmarkConsumeString(encoded);
        }
      }});

  struct BitseryFixture {
    BenchmarkHashMap<int, String> payload;
    uint64_t serializedBytesPerIteration = 0;
  };

  auto bitseryFixture = std::make_shared<BitseryFixture>();
  bitseryFixture->payload = makeStringMapPayload(48, 48);
  {
    String buffer;
    bitseryFixture->serializedBytesPerIteration = BitseryEngine::serialize(buffer, bitseryFixture->payload);
  }

  benchmarks.push_back(BenchmarkDefinition {
      .name = "serialization.bitsery.serialize_string_map",
      .description = "Serialize a representative bytell_hash_map<int, String> payload.",
      .operationsPerIteration = 1,
      .bytesPerIteration = bitseryFixture->serializedBytesPerIteration,
      .run = [bitseryFixture](uint64_t iterations) -> void {
        String serialized;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          serialized.clear();
          uint32_t bytes = BitseryEngine::serialize(serialized, bitseryFixture->payload);
          if (bytes == 0)
          {
            throw std::runtime_error("Bitsery serialize-string-map benchmark failed");
          }
          benchmarkConsume(bytes);
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "serialization.bitsery.deserialize_string_map",
      .description = "Deserialize a representative bytell_hash_map<int, String> payload.",
      .operationsPerIteration = 1,
      .bytesPerIteration = bitseryFixture->serializedBytesPerIteration,
      .run = [bitseryFixture](uint64_t iterations) -> void {
        String serialized;
        if (BitseryEngine::serialize(serialized, bitseryFixture->payload) == 0)
        {
          throw std::runtime_error("Bitsery deserialize-string-map setup failed");
        }

        BenchmarkHashMap<int, String> decoded;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          decoded.clear();
          if (BitseryEngine::deserializeSafe(serialized, decoded) == false)
          {
            throw std::runtime_error("Bitsery deserialize-string-map benchmark failed");
          }
          benchmarkConsume(decoded.size());
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "serialization.bitsery.roundtrip_string_map",
      .description = "Serialize and deserialize a representative bytell_hash_map<int, String> payload.",
      .operationsPerIteration = 1,
      .bytesPerIteration = bitseryFixture->serializedBytesPerIteration * 2,
      .run = [bitseryFixture](uint64_t iterations) -> void {
        String serialized;
        BenchmarkHashMap<int, String> decoded;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          serialized.clear();
          decoded.clear();
          uint32_t bytes = BitseryEngine::serialize(serialized, bitseryFixture->payload);
          if (bytes == 0 || BitseryEngine::deserializeSafe(serialized, decoded) == false)
          {
            throw std::runtime_error("Bitsery round-trip benchmark failed");
          }
          benchmarkConsume(bytes + decoded.size());
        }
      }});

  struct BitseryVectorFixture {
    Vector<uint32_t> payload;
    uint64_t serializedBytesPerIteration = 0;
  };

  auto bitseryVectorFixture = std::make_shared<BitseryVectorFixture>();
  bitseryVectorFixture->payload.reserve(1024);
  for (uint32_t index = 0; index < 1024; ++index)
  {
    bitseryVectorFixture->payload.push_back(index * 7U);
  }
  {
    String buffer;
    bitseryVectorFixture->serializedBytesPerIteration = BitseryEngine::serialize(buffer, bitseryVectorFixture->payload);
  }

  benchmarks.push_back(BenchmarkDefinition {
      .name = "serialization.bitsery.serialize_u32_vector_1024",
      .description = "Serialize a contiguous Vector<uint32_t> payload with 1024 elements.",
      .operationsPerIteration = 1,
      .bytesPerIteration = bitseryVectorFixture->serializedBytesPerIteration,
      .run = [bitseryVectorFixture](uint64_t iterations) -> void {
        String serialized;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          serialized.clear();
          uint32_t bytes = BitseryEngine::serialize(serialized, bitseryVectorFixture->payload);
          if (bytes == 0)
          {
            throw std::runtime_error("Bitsery serialize-vector benchmark failed");
          }
          benchmarkConsume(bytes);
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "serialization.bitsery.deserialize_u32_vector_1024",
      .description = "Deserialize a contiguous Vector<uint32_t> payload with 1024 elements.",
      .operationsPerIteration = 1,
      .bytesPerIteration = bitseryVectorFixture->serializedBytesPerIteration,
      .run = [bitseryVectorFixture](uint64_t iterations) -> void {
        String serialized;
        if (BitseryEngine::serialize(serialized, bitseryVectorFixture->payload) == 0)
        {
          throw std::runtime_error("Bitsery deserialize-vector setup failed");
        }

        Vector<uint32_t> decoded;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          decoded.clear();
          if (BitseryEngine::deserializeSafe(serialized, decoded) == false)
          {
            throw std::runtime_error("Bitsery deserialize-vector benchmark failed");
          }
          benchmarkConsume(decoded.size());
        }
      }});

  struct StreamFixture {
    BenchmarkHashMap<int, String> payload;
    uint64_t frameBytesPerIteration = 0;
  };

  auto streamFixture = std::make_shared<StreamFixture>();
  streamFixture->payload = makeStringMapPayload(48, 64);
  {
    String frame;
    Message::constructSerialized(frame, streamFixture->payload, uint16_t(7));
    streamFixture->frameBytesPerIteration = frame.size();
  }

  benchmarks.push_back(BenchmarkDefinition {
      .name = "scenario.message.construct_serialized_map",
      .description = "Construct a serialized Message frame directly into the destination wire buffer.",
      .operationsPerIteration = 1,
      .bytesPerIteration = streamFixture->frameBytesPerIteration,
      .run = [streamFixture](uint64_t iterations) -> void {
        String frame;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          frame.clear();
          Message::constructSerialized(frame, streamFixture->payload, uint16_t(7));
          benchmarkConsume(frame.size());
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "scenario.stream.construct_extract_serialized_map",
      .description = "Construct a serialized Message frame and extract it through Stream framing.",
      .operationsPerIteration = 1,
      .bytesPerIteration = streamFixture->frameBytesPerIteration,
      .run = [streamFixture](uint64_t iterations) -> void {
        String frame;
        Stream stream;
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          frame.clear();
          Message::constructSerialized(frame, streamFixture->payload, uint16_t(7));
          stream.rBuffer.reset();
          stream.rBuffer.append(frame);

          bool failed = false;
          Message *message = stream.hasMessage<Message>(16, UINT32_MAX, failed);
          if (failed || message == nullptr)
          {
            throw std::runtime_error("Stream construct/extract benchmark failed");
          }

          benchmarkConsume(message->payloadSize());
          stream.consumeHeadMessage<Message>();
        }
      }});

  auto tlsMaterial = std::make_shared<TLSMaterial>(readPeerMaterial("peer-a"));

  benchmarks.push_back(BenchmarkDefinition {
      .name = "scenario.tls.generate_ctx_from_pem",
      .description = "Create and destroy an SSL_CTX from in-memory PEM material.",
      .operationsPerIteration = 1,
      .bytesPerIteration = tlsMaterial->chain.size() + tlsMaterial->cert.size() + tlsMaterial->key.size(),
      .run = [tlsMaterial](uint64_t iterations) -> void {
        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          SSL_CTX *context = TLSBase::generateCtxFromPEM(
              tlsMaterial->chain.data(), static_cast<uint32_t>(tlsMaterial->chain.size()),
              tlsMaterial->cert.data(), static_cast<uint32_t>(tlsMaterial->cert.size()),
              tlsMaterial->key.data(), static_cast<uint32_t>(tlsMaterial->key.size()));
          if (context == nullptr)
          {
            throw std::runtime_error("TLS generateCtxFromPEM benchmark failed");
          }
          benchmarkConsume(uint64_t(SSL_CTX_get_verify_mode(context)));
          SSL_CTX_free(context);
        }
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "scenario.tls.handshake_memory_bio",
      .description = "Negotiate TLS over memory BIOs with preloaded in-memory contexts.",
      .operationsPerIteration = 1,
      .bytesPerIteration = 0,
      .run = [tlsMaterial](uint64_t iterations) -> void {
        SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
            tlsMaterial->chain.data(), static_cast<uint32_t>(tlsMaterial->chain.size()),
            tlsMaterial->cert.data(), static_cast<uint32_t>(tlsMaterial->cert.size()),
            tlsMaterial->key.data(), static_cast<uint32_t>(tlsMaterial->key.size()));
        SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
            tlsMaterial->chain.data(), static_cast<uint32_t>(tlsMaterial->chain.size()),
            tlsMaterial->cert.data(), static_cast<uint32_t>(tlsMaterial->cert.size()),
            tlsMaterial->key.data(), static_cast<uint32_t>(tlsMaterial->key.size()));
        if (clientContext == nullptr || serverContext == nullptr)
        {
          freeCtx(clientContext);
          freeCtx(serverContext);
          throw std::runtime_error("TLS handshake benchmark failed to create contexts");
        }

        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          TLSBase client(clientContext, false);
          TLSBase server(serverContext, true);
          Buffer clientWire(4096, MemoryType::heap);
          Buffer clientPlain(4096, MemoryType::heap);
          Buffer serverWire(4096, MemoryType::heap);
          Buffer serverPlain(4096, MemoryType::heap);

          if (negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain) == false)
          {
            freeCtx(clientContext);
            freeCtx(serverContext);
            throw std::runtime_error("TLS handshake benchmark failed");
          }

          benchmarkConsume(uint64_t(client.isTLSNegotiated()) + (uint64_t(server.isTLSNegotiated()) << 1));
        }

        freeCtx(clientContext);
        freeCtx(serverContext);
      }});

  benchmarks.push_back(BenchmarkDefinition {
      .name = "scenario.tls.steady_state_roundtrip_4k",
      .description = "Bidirectional encrypted TLS read/write after one negotiated handshake.",
      .operationsPerIteration = 2,
      .bytesPerIteration = 8192,
      .run = [tlsMaterial](uint64_t iterations) -> void {
        SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
            tlsMaterial->chain.data(), static_cast<uint32_t>(tlsMaterial->chain.size()),
            tlsMaterial->cert.data(), static_cast<uint32_t>(tlsMaterial->cert.size()),
            tlsMaterial->key.data(), static_cast<uint32_t>(tlsMaterial->key.size()));
        SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
            tlsMaterial->chain.data(), static_cast<uint32_t>(tlsMaterial->chain.size()),
            tlsMaterial->cert.data(), static_cast<uint32_t>(tlsMaterial->cert.size()),
            tlsMaterial->key.data(), static_cast<uint32_t>(tlsMaterial->key.size()));
        if (clientContext == nullptr || serverContext == nullptr)
        {
          freeCtx(clientContext);
          freeCtx(serverContext);
          throw std::runtime_error("TLS steady-state benchmark failed to create contexts");
        }

        TLSBase client(clientContext, false);
        TLSBase server(serverContext, true);
        Buffer clientWire(8192, MemoryType::heap);
        Buffer clientPlain(8192, MemoryType::heap);
        Buffer serverWire(8192, MemoryType::heap);
        Buffer serverPlain(8192, MemoryType::heap);
        String payload = makeDeterministicPayload(4096);

        if (negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain) == false)
        {
          freeCtx(clientContext);
          freeCtx(serverContext);
          throw std::runtime_error("TLS steady-state benchmark failed to negotiate TLS");
        }

        for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        {
          bool madeProgress = false;

          clientWire.reset();
          serverPlain.reset();
          clientWire.append(payload.data(), payload.size());
          if (pumpTLS(client, clientWire, server, serverPlain, madeProgress) == false || madeProgress == false)
          {
            freeCtx(clientContext);
            freeCtx(serverContext);
            throw std::runtime_error("TLS steady-state benchmark client->server transfer failed");
          }
          if (serverPlain.size() != payload.size() || std::memcmp(serverPlain.data(), payload.data(), payload.size()) != 0)
          {
            freeCtx(clientContext);
            freeCtx(serverContext);
            throw std::runtime_error("TLS steady-state benchmark client->server payload mismatch");
          }

          madeProgress = false;
          serverWire.reset();
          clientPlain.reset();
          serverWire.append(payload.data(), payload.size());
          if (pumpTLS(server, serverWire, client, clientPlain, madeProgress) == false || madeProgress == false)
          {
            freeCtx(clientContext);
            freeCtx(serverContext);
            throw std::runtime_error("TLS steady-state benchmark server->client transfer failed");
          }
          if (clientPlain.size() != payload.size() || std::memcmp(clientPlain.data(), payload.data(), payload.size()) != 0)
          {
            freeCtx(clientContext);
            freeCtx(serverContext);
            throw std::runtime_error("TLS steady-state benchmark server->client payload mismatch");
          }

          benchmarkConsume(serverPlain.size() + clientPlain.size());
        }

        freeCtx(clientContext);
        freeCtx(serverContext);
      }});

  return benchmarks;
}

} // namespace

int main(int argc, char **argv)
{
  try
  {
    BenchmarkOptions options = parseOptions(argc, argv);
    Hasher::setGlobalSeed(kBenchmarkHasherSeed);
    std::vector<BenchmarkDefinition> benchmarks = makeBenchmarks();

    std::vector<const BenchmarkDefinition *> selected;
    selected.reserve(benchmarks.size());
    for (const BenchmarkDefinition& benchmark : benchmarks)
    {
      if (matchesSelection(benchmark, options))
      {
        selected.push_back(&benchmark);
      }
    }

    if (selected.empty())
    {
      std::cerr << "No benchmarks matched";
      if (!options.filter.empty())
      {
        std::cerr << " filter '" << options.filter << '\'';
      }
      else if (!options.exact.empty())
      {
        std::cerr << " exact '" << options.exact << '\'';
      }
      std::cerr << ".\n";
      return 2;
    }

    if (options.listOnly)
    {
      for (const BenchmarkDefinition *benchmark : selected)
      {
        std::cout << benchmark->name << '\t' << benchmark->description << '\n';
      }
      return 0;
    }

    std::cout << "benchmark_count=" << selected.size()
              << " min_time_ms=" << options.minTimeMs
              << " warmup_runs=" << options.warmupRuns
              << " repetitions=" << options.repetitions
              << " use_mimalloc=" << USE_MIMALLOC
              << " allocator_mode=" << benchmarkAllocatorMode()
              << " hasher_seed_policy=global_shared"
              << " hasher_seed=" << kBenchmarkHasherSeed;
    if (options.forcedIterations > 0)
    {
      std::cout << " iterations_override=" << options.forcedIterations;
    }
    if (!options.exact.empty())
    {
      std::cout << " exact=" << options.exact;
    }
    else if (!options.filter.empty())
    {
      std::cout << " filter=" << options.filter;
    }
    std::cout << '\n';

    for (const BenchmarkDefinition *benchmark : selected)
    {
      uint64_t iterations = options.forcedIterations > 0 ? options.forcedIterations
                                                         : calibrateIterations(*benchmark, options.minTimeMs);
      std::vector<uint64_t> samples;
      samples.reserve(options.repetitions);

      for (uint32_t warmup = 0; warmup < options.warmupRuns; ++warmup)
      {
        benchmark->run(iterations);
      }

      for (uint32_t repetition = 0; repetition < options.repetitions; ++repetition)
      {
        samples.push_back(measureNanoseconds(*benchmark, iterations));
      }

      printResult(*benchmark, iterations, samples);
    }
  }
  catch (const std::exception& error)
  {
    std::cerr << "benchmark harness failed: " << error.what() << '\n';
    return 1;
  }

  return int(g_benchmark_sink == 0xffffffffffffffffULL);
}
