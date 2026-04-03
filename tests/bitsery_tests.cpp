// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include "services/bitsery.h"

namespace {

struct FixedBinaryBlob {

  uint8_t bytes[16] {};
  uint8_t tag = 0;
};

template <typename S>
static void serialize(S& serializer, FixedBinaryBlob& blob)
{
  uint8_t *bytes = blob.bytes;
  serializer.ext(bytes, bitsery::ext::FixedBinarySequence<16> {});
  serializer.value1b(blob.tag);
}

template <typename T>
static String serializeObject(TestSuite& suite, T& object)
{
  String buffer;
  EXPECT_TRUE(suite, BitseryEngine::serialize(buffer, object) > 0);
  return buffer;
}

template <typename T>
static void expectAllTruncationsFail(TestSuite& suite, T& source)
{
  String serialized = serializeObject(suite, source);

  for (uint64_t truncatedSize = 0; truncatedSize < serialized.size(); ++truncatedSize)
  {
    String truncated(serialized.data(), truncatedSize, Copy::yes, truncatedSize);
    T decoded;
    EXPECT_FALSE(suite, BitseryEngine::deserializeSafe(truncated, decoded));
  }
}

template <typename T>
static void expectInflatedPrefixSizeFails(TestSuite& suite, T& source)
{
  String serialized = serializeObject(suite, source);
  EXPECT_TRUE(suite, serialized.size() > 0);
  if (serialized.size() == 0)
  {
    return;
  }

  EXPECT_TRUE(suite, serialized[0] < 0x80);
  if (serialized[0] >= 0x80)
  {
    return;
  }

  String corrupted = serialized;
  corrupted[0] = uint8_t(corrupted[0] + 1);

  T decoded;
  EXPECT_FALSE(suite, BitseryEngine::deserializeSafe(corrupted, decoded));
}

static void testFixedBinarySequenceRoundTrip(TestSuite& suite)
{
  FixedBinaryBlob source;
  for (uint8_t index = 0; index < 16; ++index)
  {
    source.bytes[index] = uint8_t(index * 3);
  }
  source.tag = 9;

  String serialized = serializeObject(suite, source);

  FixedBinaryBlob decoded {};
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_EQ(suite, decoded.tag, source.tag);
  EXPECT_EQ(suite, std::memcmp(decoded.bytes, source.bytes, sizeof(source.bytes)), 0);

  expectAllTruncationsFail(suite, source);
}

static void testStringRoundTripAndFailures(TestSuite& suite)
{
  String source;
  EXPECT_TRUE(suite, source.reserve(64));
  source.assign("bitsery-string");
  uint64_t sourceCapacity = source.tentativeCapacity();
  EXPECT_TRUE(suite, sourceCapacity > source.size());

  String serialized = serializeObject(suite, source);

  String decoded("tiny");
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_STRING_EQ(suite, decoded, source);
  EXPECT_EQ(suite, decoded.size(), source.size());
  EXPECT_TRUE(suite, decoded.tentativeCapacity() >= source.size());

  expectAllTruncationsFail(suite, source);
  expectInflatedPrefixSizeFails(suite, source);
}

static void testVectorRoundTripAndFailures(TestSuite& suite)
{
  Vector<uint32_t> source;
  source.push_back(7);
  source.push_back(70);
  source.push_back(700);

  String serialized = serializeObject(suite, source);

  Vector<uint32_t> decoded;
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_EQ(suite, decoded.size(), source.size());
  EXPECT_EQ(suite, decoded[0], source[0]);
  EXPECT_EQ(suite, decoded[1], source[1]);
  EXPECT_EQ(suite, decoded[2], source[2]);

  expectAllTruncationsFail(suite, source);
  expectInflatedPrefixSizeFails(suite, source);
}

static void testBytellHashMapRoundTripAndFailures(TestSuite& suite)
{
  bytell_hash_map<int, String> source;
  source.insert_or_assign(1, String("one"));
  source.insert_or_assign(2, String("two"));

  String serialized = serializeObject(suite, source);

  bytell_hash_map<int, String> decoded;
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_EQ(suite, decoded.size(), source.size());
  EXPECT_TRUE(suite, decoded.contains(1));
  EXPECT_TRUE(suite, decoded.contains(2));
  EXPECT_STRING_EQ(suite, decoded.find(1)->second, "one"_ctv);
  EXPECT_STRING_EQ(suite, decoded.find(2)->second, "two"_ctv);

  expectAllTruncationsFail(suite, source);
  expectInflatedPrefixSizeFails(suite, source);
}

static void testBytellHashSetRoundTripAndFailures(TestSuite& suite)
{
  bytell_hash_set<String> source;
  source.insert(String("alpha"));
  source.insert(String("beta"));

  String serialized = serializeObject(suite, source);

  bytell_hash_set<String> decoded;
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_EQ(suite, decoded.size(), source.size());
  EXPECT_TRUE(suite, decoded.contains(String("alpha")));
  EXPECT_TRUE(suite, decoded.contains(String("beta")));

  expectAllTruncationsFail(suite, source);
  expectInflatedPrefixSizeFails(suite, source);
}

static void testBytellHashSubvectorRoundTripAndFailures(TestSuite& suite)
{
  bytell_hash_subvector<int, String> source;
  source.insert(5, String("first"));
  source.insert(5, String("second"));
  source.insert(7, String("third"));

  String serialized = serializeObject(suite, source);

  bytell_hash_subvector<int, String> decoded;
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serialized, decoded));
  EXPECT_EQ(suite, decoded.size(), uint32_t(2));
  EXPECT_TRUE(suite, decoded.hasEntryFor(5, String("first")));
  EXPECT_TRUE(suite, decoded.hasEntryFor(5, String("second")));
  EXPECT_TRUE(suite, decoded.hasEntryFor(7, String("third")));
  EXPECT_EQ(suite, decoded.countEntriesFor(5), uint32_t(2));
  EXPECT_EQ(suite, decoded.countEntriesFor(7), uint32_t(1));

  expectAllTruncationsFail(suite, source);
  expectInflatedPrefixSizeFails(suite, source);
}

} // namespace

int main()
{
  TestSuite suite;

  testFixedBinarySequenceRoundTrip(suite);
  testStringRoundTripAndFailures(suite);
  testVectorRoundTripAndFailures(suite);
  testBytellHashMapRoundTripAndFailures(suite);
  testBytellHashSetRoundTripAndFailures(suite);
  testBytellHashSubvectorRoundTripAndFailures(suite);

  return suite.finish("bitsery tests");
}
