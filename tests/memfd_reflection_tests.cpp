// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <string_view>
#include <unistd.h>

#include "base/reflection.h"
#include "services/memfd.h"

namespace {

struct ReflectionProbeType {
  int value = 0;
};

static void closeIfOpen(int fd)
{
  if (fd >= 0)
  {
    close(fd);
  }
}

static void testReflectionTypeNames(TestSuite& suite)
{
  std::string_view intName = type_name<int>();
  std::string_view probeName = type_name<ReflectionProbeType>();
  std::string_view stringName = type_name<String>();

  EXPECT_FALSE(suite, intName.empty());
  EXPECT_TRUE(suite, intName.find("int") != std::string_view::npos);
  EXPECT_TRUE(suite, probeName.find("ReflectionProbeType") != std::string_view::npos);
  EXPECT_TRUE(suite, stringName.find("String") != std::string_view::npos);
}

static void testMemfdRoundTripAndRewind(TestSuite& suite)
{
  int fd = Memfd::create("basics-memfd-roundtrip"_ctv);
  EXPECT_TRUE(suite, fd >= 0);
  if (fd < 0)
  {
    return;
  }

  String payload("payload-from-memfd");
  EXPECT_TRUE(suite, Memfd::writeAll(fd, payload));
  EXPECT_TRUE(suite, lseek(fd, 3, SEEK_SET) >= 0);

  String output;
  EXPECT_TRUE(suite, Memfd::readAll(fd, output));
  EXPECT_STRING_EQ(suite, output, payload);

  closeIfOpen(fd);
}

static void testMemfdDuplicateToFixedFd(TestSuite& suite)
{
  int fd = Memfd::create("basics-memfd-dup"_ctv);
  EXPECT_TRUE(suite, fd >= 0);
  if (fd < 0)
  {
    return;
  }

  String payload("duplicated-fd-payload");
  EXPECT_TRUE(suite, Memfd::writeAll(fd, payload));

  int fixedFd = 257;
  closeIfOpen(fixedFd);
  EXPECT_TRUE(suite, Memfd::dupTo(fd, fixedFd));

  String output;
  EXPECT_TRUE(suite, Memfd::readAll(fixedFd, output));
  EXPECT_STRING_EQ(suite, output, payload);

  closeIfOpen(fixedFd);
  closeIfOpen(fd);
}

static void testMemfdRejectsEmptyAndInvalidDescriptors(TestSuite& suite)
{
  String output;
  EXPECT_FALSE(suite, Memfd::readAll(-1, output));
  EXPECT_FALSE(suite, Memfd::dupTo(-1, 42));
  EXPECT_FALSE(suite, Memfd::dupTo(42, -1));

  int fd = Memfd::create("basics-memfd-empty"_ctv);
  EXPECT_TRUE(suite, fd >= 0);
  if (fd >= 0)
  {
    EXPECT_FALSE(suite, Memfd::readAll(fd, output));
  }

  closeIfOpen(fd);
}

} // namespace

int main()
{
  TestSuite suite;
  testReflectionTypeNames(suite);
  testMemfdRoundTripAndRewind(suite);
  testMemfdDuplicateToFixedFd(suite);
  testMemfdRejectsEmptyAndInvalidDescriptors(suite);
  return suite.finish("basics_memfd_reflection_tests");
}
