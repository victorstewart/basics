// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <limits>

#include "tests/test_support.h"
#include "types/types.containers.h"

static void testRawBufferConstructorRespectsExplicitLength(TestSuite& suite)
{
  uint8_t bytes[] = {'a', 'b', 'c', 'd', 'e'};

  String copied(bytes, sizeof(bytes), Copy::yes, 3);
  EXPECT_EQ(suite, copied.size(), uint64_t(3));
  EXPECT_STRING_EQ(suite, copied, "abc"_ctv);

  bytes[0] = 'z';
  EXPECT_STRING_EQ(suite, copied, "abc"_ctv);

  String viewed(bytes, sizeof(bytes), Copy::no, 3);
  EXPECT_EQ(suite, viewed.size(), uint64_t(3));
  EXPECT_EQ(suite, viewed.tentativeCapacity(), uint64_t(sizeof(bytes)));
  EXPECT_STRING_EQ(suite, viewed, "zbc"_ctv);
}

static void testViewCopyPreservesLogicalLength(TestSuite& suite)
{
  uint8_t storage[] = {'x', 'y', 'z', 'w'};
  String view(storage, sizeof(storage), Copy::no, 2);
  String copiedView = view;

  EXPECT_EQ(suite, copiedView.size(), uint64_t(2));
  EXPECT_EQ(suite, copiedView.tentativeCapacity(), uint64_t(sizeof(storage)));
  EXPECT_STRING_EQ(suite, copiedView, "xy"_ctv);

  Buffer buffer;
  buffer.setInvariant(storage, sizeof(storage), 0);
  Buffer copiedBuffer = buffer;
  EXPECT_EQ(suite, copiedBuffer.size(), uint64_t(0));
  EXPECT_EQ(suite, copiedBuffer.tentativeCapacity(), uint64_t(sizeof(storage)));
}

static void testSubstrClampsToBounds(TestSuite& suite)
{
  String text("hello");

  String tail = text.substr(1, 32, Copy::yes);
  EXPECT_STRING_EQ(suite, tail, "ello"_ctv);

  String last = text.substr(4, 8, Copy::no);
  EXPECT_EQ(suite, last.size(), uint64_t(1));
  EXPECT_STRING_EQ(suite, last, "o"_ctv);

  String empty = text.substr(99, 4, Copy::yes);
  EXPECT_TRUE(suite, empty.empty());
}

static void testAsRequiresEnoughBytes(TestSuite& suite)
{
  String bytes;
  uint32_t expected = 0x78563412;
  bytes.append(expected);
  EXPECT_EQ(suite, bytes.as<uint32_t>(), expected);

  String shortBytes;
  shortBytes.append(uint8_t(0x12));
  EXPECT_EQ(suite, shortBytes.as<uint32_t>(), uint32_t(0));
  EXPECT_EQ(suite, shortBytes.as<uint16_t>(), uint16_t(0));
}

static void testLengthMutatorsClamp(TestSuite& suite)
{
  String text("abcd");
  text.trim(99);
  EXPECT_EQ(suite, text.size(), uint64_t(0));

  EXPECT_TRUE(suite, text.reserve(8));
  text.resize(999);
  EXPECT_EQ(suite, text.size(), text.tentativeCapacity());

  text.advance(999);
  EXPECT_EQ(suite, text.size(), text.tentativeCapacity());

  text.setTail(text.data() + text.tentativeCapacity());
  EXPECT_EQ(suite, text.size(), text.tentativeCapacity());

  String empty;
  empty.setTail(nullptr);
  EXPECT_EQ(suite, empty.size(), uint64_t(0));
}

static void testEmptyAlignedAppendStillAlignsTail(TestSuite& suite)
{
  String destination;
  EXPECT_TRUE(suite, destination.reserve(32));
  destination.append(uint8_t(0x5a));

  const String empty;
  EXPECT_EQ(suite, empty.data(), nullptr);

  uintptr_t unalignedTail = reinterpret_cast<uintptr_t>(destination.data() + destination.size());
  uint64_t expectedPadding = (-unalignedTail) & (uint64_t(Alignment::eight) - 1);
  destination.alignedAppend<Alignment::eight>(empty);

  EXPECT_EQ(suite, destination.size(), uint64_t(1) + expectedPadding);
  EXPECT_EQ(suite, reinterpret_cast<uintptr_t>(destination.data() + destination.size()) % uint64_t(Alignment::eight), uintptr_t(0));
  EXPECT_EQ(suite, destination.data()[0], uint8_t(0x5a));
}

static void testNeedUsesGeometricGrowth(TestSuite& suite)
{
  String builder;
  EXPECT_TRUE(suite, builder.reserve(32));
  uint64_t previousCapacity = builder.tentativeCapacity();
  builder.resize(previousCapacity);

  builder.append(reinterpret_cast<const uint8_t *>("b"), 1);

  EXPECT_TRUE(suite, previousCapacity >= uint64_t(32));
  EXPECT_TRUE(suite, builder.tentativeCapacity() >= (previousCapacity * 2));
  EXPECT_TRUE(suite, builder.tentativeCapacity() > builder.size());
}

static void testCopyAssignmentReusesHeapStorage(TestSuite& suite)
{
  String destination;
  EXPECT_TRUE(suite, destination.reserve(128));
  destination.assign("original");
  uint8_t *originalStorage = destination.data();
  uint64_t originalCapacity = destination.tentativeCapacity();

  String source("after");
  destination = source;

  EXPECT_EQ(suite, destination.data(), originalStorage);
  EXPECT_EQ(suite, destination.tentativeCapacity(), originalCapacity);
  EXPECT_STRING_EQ(suite, destination, "after"_ctv);
}

static void testFormatterNumericTokens(TestSuite& suite)
{
  String output;
  output.snprintf<"int={itoa} hex={itoh} float={dtoa:2}"_ctv>(int64_t(-42), uint32_t(0x1f), 3.14159);

  EXPECT_STRING_EQ(suite, output, "int=-42 hex=0x1f float=3.14"_ctv);

  constexpr uint128_t uuid = (uint128_t(0x08537fb70ea8d4bc) << 64) | 0x789b3da6ccacf74f;
  String assigned;
  assigned.assignItoa(uuid);
  EXPECT_STRING_EQ(suite, assigned, "11067374974848015842483059175252096847"_ctv);

  output.snprintf<"uuid={itoa}"_ctv>(uuid);
  EXPECT_STRING_EQ(suite, output, "uuid=11067374974848015842483059175252096847"_ctv);
}

static void testIntegerDecimalBoundaries(TestSuite& suite)
{
  String falseValue(false);
  String trueValue(true);
  EXPECT_STRING_EQ(suite, falseValue, "0"_ctv);
  EXPECT_STRING_EQ(suite, trueValue, "1"_ctv);

  String zero(uint128_t(0));
  EXPECT_STRING_EQ(suite, zero, "0"_ctv);

  String unsignedMaximum(std::numeric_limits<uint128_t>::max());
  EXPECT_STRING_EQ(suite, unsignedMaximum, "340282366920938463463374607431768211455"_ctv);

  String signedMinimum(std::numeric_limits<int128_t>::min());
  EXPECT_STRING_EQ(suite, signedMinimum, "-170141183460469231731687303715884105728"_ctv);
}

static void testAppendTabsAndPlus(TestSuite& suite)
{
  String tabs;
  tabs.appendTabs(8);
  EXPECT_STRING_EQ(suite, tabs, "\t\t\t\t\t\t\t\t"_ctv);

  String left("hello");
  String right("world");
  EXPECT_STRING_EQ(suite, left + right, "helloworld"_ctv);
  EXPECT_STRING_EQ(suite, left + ""_ctv, "hello"_ctv);
}

static void testVectorEqualityIsElementWise(TestSuite& suite)
{
  static_assert(StringType<Vector<uint8_t>>);
  static_assert(!StringType<Vector<uint16_t>>);
  static_assert(StringPointerType<Vector<uint8_t> *>);
  static_assert(!StringPointerType<Vector<uint16_t> *>);

  Vector<uint16_t> left = {1, 2};
  Vector<uint16_t> same = {1, 2};
  Vector<uint16_t> different = {1, 3};
  Vector<uint32_t> threeElements = {0, 0, 0};
  EXPECT_EQ(suite, threeElements.size(), uint64_t(3));
  EXPECT_TRUE(suite, left == same);
  EXPECT_FALSE(suite, left != same);
  EXPECT_FALSE(suite, left == different);
  EXPECT_TRUE(suite, left != different);
}

static void testCStringAndSecureReset(TestSuite& suite)
{
  String empty;
  EXPECT_EQ(suite, empty.data(), nullptr);
  const char *emptyCString = empty.c_str();
  EXPECT_TRUE(suite, emptyCString != nullptr);
  EXPECT_EQ(suite, std::strcmp(emptyCString, ""), 0);
  EXPECT_EQ(suite, empty.data(), nullptr);

  String text("hello");
  const char *textCString = text.c_str();
  EXPECT_TRUE(suite, textCString != nullptr);
  EXPECT_EQ(suite, std::strcmp(textCString, "hello"), 0);

  String compileTimeAssigned("before");
  compileTimeAssigned = "lo"_ctv;
  const char *assignedCString = compileTimeAssigned.c_str();
  EXPECT_TRUE(suite, assignedCString != nullptr);
  EXPECT_EQ(suite, std::strcmp(assignedCString, "lo"), 0);

  String compileTimeConstructed("route"_ctv);
  const char *constructedCString = compileTimeConstructed.c_str();
  EXPECT_TRUE(suite, constructedCString != nullptr);
  EXPECT_EQ(suite, std::strcmp(constructedCString, "route"), 0);

  text.secureReset();
  EXPECT_TRUE(suite, text.empty());
  EXPECT_EQ(suite, text.data(), nullptr);
}

static void testReserveFailurePreservesHeapState(TestSuite& suite)
{
  String text("abc");
  uint8_t *originalData = text.data();
  uint64_t originalCapacity = text.tentativeCapacity();

  EXPECT_FALSE(suite, text.reserve(std::numeric_limits<uint64_t>::max()));
  EXPECT_STRING_EQ(suite, text, "abc"_ctv);
  EXPECT_EQ(suite, text.data(), originalData);
  EXPECT_EQ(suite, text.tentativeCapacity(), originalCapacity);
}

static void testReserveFailurePreservesMmapState(TestSuite& suite)
{
  String mapped(64, MemoryType::mmap);
  EXPECT_TRUE(suite, mapped.data() != nullptr);
  if (mapped.data() == nullptr)
  {
    return;
  }

  mapped.assign("abc");
  uint8_t *originalData = mapped.data();
  uint64_t originalCapacity = mapped.tentativeCapacity();

  EXPECT_FALSE(suite, mapped.reserve(std::numeric_limits<uint64_t>::max()));
  EXPECT_STRING_EQ(suite, mapped, "abc"_ctv);
  EXPECT_EQ(suite, mapped.data(), originalData);
  EXPECT_EQ(suite, mapped.tentativeCapacity(), originalCapacity);
}

static void testReadOnlyProvenanceAndMutableViews(TestSuite& suite)
{
  String readOnly("read-only"_ctv);
  uint8_t *originalData = readOnly.data();
  EXPECT_FALSE(suite, readOnly.reserve(1));
  readOnly.append('x');
  readOnly.zeroOut();
  EXPECT_STRING_EQ(suite, readOnly, "read-only"_ctv);

  String copied = readOnly;
  EXPECT_FALSE(suite, copied.reserve(1));

  String substring = readOnly.substr(1, 4, Copy::no);
  EXPECT_STRING_EQ(suite, substring, "ead-"_ctv);
  EXPECT_FALSE(suite, substring.reserve(1));
  substring.zeroOut();
  EXPECT_STRING_EQ(suite, substring, "ead-"_ctv);

  auto compileTime = "compile-time"_ctv;
  String converted = compileTime.operator String();
  EXPECT_FALSE(suite, converted.reserve(1));

  const char constant[] = "constant";
  String constantView;
  constantView.setInvariant(constant, sizeof(constant), sizeof(constant) - 1);
  EXPECT_FALSE(suite, constantView.reserve(1));

  std::string_view standardView("standard");
  String constructedStandardView(standardView, Copy::no);
  EXPECT_FALSE(suite, constructedStandardView.reserve(1));

  String invariantStandardView;
  invariantStandardView.setInvariant(standardView);
  EXPECT_FALSE(suite, invariantStandardView.reserve(1));

  readOnly.secureReset();
  EXPECT_TRUE(suite, readOnly.empty());
  EXPECT_EQ(suite, std::memcmp(originalData, "read-only", 9), 0);

  uint8_t mutableStorage[16] = {'a', 'b', 'c'};
  String mutableView(mutableStorage, sizeof(mutableStorage), Copy::no, 3);
  EXPECT_TRUE(suite, mutableView.reserve(4));
  mutableView.append('d');
  EXPECT_STRING_EQ(suite, mutableView, "abcd"_ctv);

  String mutableSubstring = mutableView.substr(1, 2, Copy::no);
  EXPECT_TRUE(suite, mutableSubstring.reserve(1));
  mutableSubstring.zeroOut();
  EXPECT_EQ(suite, mutableStorage[1], uint8_t(0));
  EXPECT_EQ(suite, mutableStorage[2], uint8_t(0));

  String invariantMutableView;
  invariantMutableView.setInvariant(mutableStorage, sizeof(mutableStorage), 0);
  EXPECT_TRUE(suite, invariantMutableView.reserve(1));
  invariantMutableView.append('x');
  EXPECT_EQ(suite, mutableStorage[0], uint8_t('x'));
  EXPECT_FALSE(suite, invariantMutableView.reserve(sizeof(mutableStorage) + 1));
}

int main()
{
  TestSuite suite;

  testRawBufferConstructorRespectsExplicitLength(suite);
  testViewCopyPreservesLogicalLength(suite);
  testSubstrClampsToBounds(suite);
  testAsRequiresEnoughBytes(suite);
  testLengthMutatorsClamp(suite);
  testEmptyAlignedAppendStillAlignsTail(suite);
  testNeedUsesGeometricGrowth(suite);
  testCopyAssignmentReusesHeapStorage(suite);
  testFormatterNumericTokens(suite);
  testIntegerDecimalBoundaries(suite);
  testAppendTabsAndPlus(suite);
  testVectorEqualityIsElementWise(suite);
  testCStringAndSecureReset(suite);
  testReserveFailurePreservesHeapState(suite);
  testReserveFailurePreservesMmapState(suite);
  testReadOnlyProvenanceAndMutableViews(suite);

  return suite.finish("string tests");
}
