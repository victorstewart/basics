// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include "types/types.containers.h"

struct ForeignByteKey {

  const uint8_t *data = nullptr;
  uint64_t size = 0;
};

template <>
struct byte_string_view_traits<ForeignByteKey> {

  constexpr static bool enabled = true;

  static ByteStringView view(const ForeignByteKey& key)
  {
    return ByteStringView {key.data, key.size};
  }
};

namespace {

struct HashableKey {

  uint64_t value = 0;

  uint64_t hash() const
  {
    return value * 1315423911ULL;
  }
};

struct EqualsOnlyKey {

  int value = 0;

  bool equals(const EqualsOnlyKey& other) const
  {
    return value == other.value;
  }
};

struct OperatorOnlyKey {

  int value = 0;

  bool operator==(const OperatorOnlyKey& other) const
  {
    return value == other.value;
  }
};

static void testNoncryptoHasher(TestSuite& suite)
{
  noncrypto_hasher hasher;

  String empty;
  String alpha("alpha");
  String alphaCopy("alpha");
  constexpr auto alphaCtv = "alpha"_ctv;
  constexpr auto alphaCtvCopy = "alpha"_ctv;

  EXPECT_EQ(suite, hasher(empty), size_t(0));
  EXPECT_EQ(suite, hasher(alpha), hasher(alphaCopy));
  EXPECT_EQ(suite, hasher(alpha), size_t(Hasher::hash<Hasher::SeedPolicy::thread_shared>(alpha.data(), alpha.size())));
  EXPECT_EQ(suite, hasher(alphaCtv), hasher(alphaCtvCopy));
  EXPECT_EQ(suite, hasher(alphaCtv), size_t(Hasher::hash<Hasher::SeedPolicy::thread_shared>(reinterpret_cast<const uint8_t *>(alphaCtv.data()), alphaCtv.size())));

  uint64_t integral = 0x0102030405060708ULL;
  EXPECT_EQ(suite, hasher(integral), size_t(Hasher::hash<Hasher::SeedPolicy::thread_shared>(reinterpret_cast<const uint8_t *>(&integral), sizeof(integral))));

  int pointedValue = 41;
  int *pointer = &pointedValue;
  EXPECT_EQ(suite, hasher(pointer), size_t(Hasher::hash<Hasher::SeedPolicy::thread_shared>(reinterpret_cast<const uint8_t *>(&pointer), sizeof(pointer))));

  HashableKey hashable {77};
  EXPECT_EQ(suite, hasher(hashable), size_t(hashable.hash()));

  ForeignByteKey foreignAlpha {reinterpret_cast<const uint8_t *>("alpha"), 5};
  ForeignByteKey foreignAlphaCopy {reinterpret_cast<const uint8_t *>("alpha"), 5};
  EXPECT_EQ(suite, hasher(foreignAlpha), hasher(foreignAlphaCopy));
}

static void testKeysAreEqual(TestSuite& suite)
{
  keys_are_equal equal;

  String alpha("alpha");
  String alphaCopy("alpha");
  String beta("beta");
  String emptyA;
  String emptyB;

  EXPECT_TRUE(suite, equal(alpha, alphaCopy));
  EXPECT_FALSE(suite, equal(alpha, beta));
  EXPECT_TRUE(suite, equal(emptyA, emptyB));

  constexpr auto alphaCtv = "alpha"_ctv;
  constexpr auto alphaCtvCopy = "alpha"_ctv;
  EXPECT_TRUE(suite, equal(alphaCtv, alphaCtvCopy));
  EXPECT_TRUE(suite, alpha == alphaCopy);
  EXPECT_FALSE(suite, alpha == beta);
  EXPECT_TRUE(suite, alpha == "alpha"_ctv);
  EXPECT_TRUE(suite, "alpha"_ctv == alpha);
  EXPECT_TRUE(suite, alphaCtv == alpha);

  ForeignByteKey foreignAlpha {reinterpret_cast<const uint8_t *>("alpha"), 5};
  ForeignByteKey foreignBeta {reinterpret_cast<const uint8_t *>("beta"), 4};
  EXPECT_TRUE(suite, equal(foreignAlpha, foreignAlpha));
  EXPECT_FALSE(suite, equal(foreignAlpha, foreignBeta));

  int left = 5;
  int leftCopy = 5;
  int right = 6;
  EXPECT_TRUE(suite, equal(left, leftCopy));
  EXPECT_FALSE(suite, equal(left, right));

  int storage = 9;
  int otherStorage = 10;
  int *pointer = &storage;
  int *pointerAlias = &storage;
  int *differentPointer = &otherStorage;
  EXPECT_TRUE(suite, equal(pointer, pointerAlias));
  EXPECT_FALSE(suite, equal(pointer, differentPointer));

  EqualsOnlyKey equalsA {17};
  EqualsOnlyKey equalsB {17};
  EqualsOnlyKey equalsC {18};
  EXPECT_TRUE(suite, equal(equalsA, equalsB));
  EXPECT_FALSE(suite, equal(equalsA, equalsC));

  OperatorOnlyKey operatorA {23};
  OperatorOnlyKey operatorB {23};
  OperatorOnlyKey operatorC {24};
  EXPECT_TRUE(suite, equal(operatorA, operatorB));
  EXPECT_FALSE(suite, equal(operatorA, operatorC));
}

static void testVectorHelpers(TestSuite& suite)
{
  Vector<int> values;
  values.push_back(1);
  values.push_back(2);
  values.push_back(2);
  values.push_back(3);

  EXPECT_TRUE(suite, values.contains(2));
  EXPECT_FALSE(suite, values.contains(9));

  values.erase(2);
  EXPECT_EQ(suite, values.size(), size_t(3));
  EXPECT_EQ(suite, values[0], 1);
  EXPECT_EQ(suite, values[1], 2);
  EXPECT_EQ(suite, values[2], 3);

  values.erase(values.begin());
  EXPECT_EQ(suite, values.size(), size_t(2));
  EXPECT_EQ(suite, values[0], 2);
  EXPECT_EQ(suite, values[1], 3);

  Vector<String> words;
  words.emplace_back("zero");
  words.emplace_back("one");
  words.emplace_back("two");

  words.erase(words.begin() + 1);
  EXPECT_EQ(suite, words.size(), size_t(2));
  EXPECT_STRING_EQ(suite, words[0], "zero"_ctv);
  EXPECT_STRING_EQ(suite, words[1], "two"_ctv);
}

static void testBytellHashSubmap(TestSuite& suite)
{
  bytell_hash_submap<int, int, String> submap;

  submap.insert_or_assign(1, 10, "ten");
  submap.insert_or_assign(1, 20, "twenty");
  submap.insert_or_assign(2, 30, "thirty");

  EXPECT_EQ(suite, submap.size(), uint32_t(2));
  EXPECT_TRUE(suite, submap.hasEntriesFor(1));
  EXPECT_EQ(suite, submap.countEntriesFor(1), uint32_t(2));
  EXPECT_TRUE(suite, submap.hasEntryFor(1, 10));
  EXPECT_FALSE(suite, submap.hasEntryFor(1, 40));
  EXPECT_STRING_EQ(suite, submap.entryFor(1, 10), "ten");

  Vector<int> seenSubkeys;
  submap.forEntries(1, [&](const auto& entry) -> void {
    seenSubkeys.push_back(entry.first);
  });
  EXPECT_EQ(suite, seenSubkeys.size(), size_t(2));
  EXPECT_TRUE(suite, seenSubkeys.contains(10));
  EXPECT_TRUE(suite, seenSubkeys.contains(20));

  EXPECT_TRUE(suite, submap.eraseEntry(1, 10));
  EXPECT_FALSE(suite, submap.hasEntryFor(1, 10));
  EXPECT_EQ(suite, submap.countEntriesFor(1), uint32_t(1));

  EXPECT_TRUE(suite, submap.eraseEntriesFor(2));
  EXPECT_FALSE(suite, submap.hasEntriesFor(2));
  EXPECT_FALSE(suite, submap.eraseEntriesFor(2));

  submap.clear();
  EXPECT_TRUE(suite, submap.isEmpty());
}

static void testBytellHashSubsetAndSubvector(TestSuite& suite)
{
  bytell_hash_subset<int, int> subset;
  subset.insert(7, 1);
  subset.emplace(7, 2);
  subset.insert(8, 3);

  EXPECT_TRUE(suite, subset.hasEntryFor(7, 1));
  EXPECT_EQ(suite, subset.countEntriesFor(7), uint32_t(2));
  EXPECT_TRUE(suite, subset.eraseEntry(7, 1));
  EXPECT_FALSE(suite, subset.hasEntryFor(7, 1));
  EXPECT_TRUE(suite, subset.hasEntriesFor(7));
  EXPECT_TRUE(suite, subset.eraseEntry(8, 3));
  EXPECT_FALSE(suite, subset.hasEntriesFor(8));

  bytell_hash_subvector<int, int> subvector;
  subvector[9].push_back(11);
  subvector.insert(5, 1);
  subvector.insert(5, 2);
  subvector.emplace(5, 3);
  subvector.insert(6, 4);

  EXPECT_TRUE(suite, subvector.hasEntryFor(5, 2));
  EXPECT_EQ(suite, subvector.countEntriesFor(5), uint32_t(3));
  EXPECT_EQ(suite, subvector.countEntriesFor(9), uint32_t(1));

  Vector<int> visited;
  subvector.forEntries(5, [&](int value) -> void {
    visited.push_back(value);
  });
  EXPECT_EQ(suite, visited.size(), size_t(3));
  EXPECT_TRUE(suite, visited.contains(1));
  EXPECT_TRUE(suite, visited.contains(2));
  EXPECT_TRUE(suite, visited.contains(3));

  subvector.eraseSomeEntriesFor(5, [&](int value) -> int {
    if (value == 2)
    {
      return 1;
    }
    if (value == 3)
    {
      return 2;
    }
    return 0;
  });

  EXPECT_FALSE(suite, subvector.hasEntryFor(5, 2));
  EXPECT_TRUE(suite, subvector.hasEntryFor(5, 1));
  EXPECT_TRUE(suite, subvector.hasEntryFor(5, 3));
  EXPECT_EQ(suite, subvector.countEntriesFor(5), uint32_t(2));

  Vector<int> erased;
  subvector.eraseAllEntriesAfter(6, [&](int value) -> void {
    erased.push_back(value);
  });
  EXPECT_EQ(suite, erased.size(), size_t(1));
  EXPECT_EQ(suite, erased[0], 4);
  EXPECT_FALSE(suite, subvector.hasEntriesFor(6));

  EXPECT_TRUE(suite, subvector.eraseEntriesFor(5));
  EXPECT_FALSE(suite, subvector.hasEntriesFor(5));
  EXPECT_TRUE(suite, subvector.eraseEntriesFor(9));
  EXPECT_TRUE(suite, subvector.isEmpty());
}

static void testAllocatorModeSensitivePath(TestSuite& suite)
{
#if USE_MIMALLOC == 2
  static_assert(std::is_same_v<VectorAllocator<int>, mi_stl_allocator<int>>);
#else
  static_assert(std::is_same_v<VectorAllocator<int>, std::allocator<int>>);
#endif

  Vector<int> vector;
  vector.push_back(1);
  vector.push_back(2);
  EXPECT_EQ(suite, vector.size(), size_t(2));

  bytell_hash_map<int, int> map;
  map.emplace(7, 70);
  EXPECT_TRUE(suite, map.contains(7));
  EXPECT_EQ(suite, map.find(7)->second, 70);

  bytell_hash_set<int> set;
  set.emplace(5);
  EXPECT_TRUE(suite, set.contains(5));
}

} // namespace

int main()
{
  TestSuite suite;

  testNoncryptoHasher(suite);
  testKeysAreEqual(suite);
  testVectorHelpers(suite);
  testBytellHashSubmap(suite);
  testBytellHashSubsetAndSubvector(suite);
  testAllocatorModeSensitivePath(suite);

  return suite.finish("containers tests");
}
