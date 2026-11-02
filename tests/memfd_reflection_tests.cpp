// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <fcntl.h>
#include <linux/memfd.h>
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

static void testMemfdExplicitFlagsPermitSealing(TestSuite& suite)
{
  int fd = Memfd::create(
      "basics-memfd-sealed"_ctv,
      MFD_ALLOW_SEALING | MFD_CLOEXEC);
  EXPECT_TRUE(suite, fd >= 0);
  if (fd < 0)
  {
    return;
  }

  const int descriptorFlags = fcntl(fd, F_GETFD);
  EXPECT_TRUE(suite, descriptorFlags >= 0);
  EXPECT_TRUE(suite, descriptorFlags >= 0 && (descriptorFlags & FD_CLOEXEC) != 0);
  String payload("sealed-payload");
  EXPECT_TRUE(suite, Memfd::writeAll(fd, payload));
  EXPECT_TRUE(suite, fcntl(
      fd,
      F_ADD_SEALS,
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
  const int seals = fcntl(fd, F_GET_SEALS);
  EXPECT_TRUE(suite, seals >= 0);
  EXPECT_TRUE(suite, seals >= 0 && (seals & F_SEAL_WRITE) != 0);
  EXPECT_FALSE(suite, Memfd::writeAll(fd, payload));

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
  testMemfdExplicitFlagsPermitSealing(suite);
  testMemfdRejectsEmptyAndInvalidDescriptors(suite);
  return suite.finish("basics_memfd_reflection_tests");
}
