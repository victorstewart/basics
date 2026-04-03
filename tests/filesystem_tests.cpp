// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <linux/openat2.h>
#include <string>
#include <unistd.h>

#include "services/filesystem.h"

namespace {

class TempDirectory {
private:

  std::array<char, 64> path_ {};
  bool valid_ = false;

public:

  TempDirectory()
  {
    std::snprintf(path_.data(), path_.size(), "/tmp/basics-filesystem-XXXXXX");
    valid_ = (mkdtemp(path_.data()) != nullptr);
  }

  ~TempDirectory()
  {
    if (valid_)
    {
      Filesystem::eraseDirectory(String(path_.data()));
    }
  }

  bool valid() const
  {
    return valid_;
  }

  void release()
  {
    valid_ = false;
  }

  const char *path() const
  {
    return path_.data();
  }
};

static std::string joinPath(const char *root, std::string_view child)
{
  std::string path(root);
  path.push_back('/');
  path.append(child);
  return path;
}

static int openRootDirectory(TestSuite& suite, const TempDirectory& tempDirectory)
{
  EXPECT_TRUE(suite, tempDirectory.valid());
  if (tempDirectory.valid() == false)
  {
    return -1;
  }

  errno = 0;
  String rootPath(tempDirectory.path());
  int rootFd = Filesystem::openDirectoryAt(-1, rootPath);
  if (rootFd < 0 && errno == ENOSYS)
  {
    std::cout << "filesystem tests skipped: openat2 is unavailable on this kernel\n";
    return -2;
  }

  EXPECT_TRUE(suite, rootFd >= 0);
  return rootFd;
}

static void testCreateOpenReadWriteRename(TestSuite& suite, bool& skipped)
{
  TempDirectory tempDirectory;
  int rootFd = openRootDirectory(suite, tempDirectory);
  if (rootFd == -2)
  {
    skipped = true;
    return;
  }
  if (rootFd < 0)
  {
    return;
  }

  String subdirName("subdir");
  int subdirFd = Filesystem::createOpenDirectoryAt(rootFd, subdirName);
  EXPECT_TRUE(suite, subdirFd >= 0);
  if (subdirFd < 0)
  {
    close(rootFd);
    return;
  }

  String payloadName("payload.txt");
  EXPECT_EQ(suite, Filesystem::openWriteAtClose(subdirFd, payloadName, "payload-data"_ctv), int("payload-data"_ctv.size()));

  String payload;
  Filesystem::openReadAtClose(subdirFd, "payload.txt"_ctv, payload);
  EXPECT_STRING_EQ(suite, payload, "payload-data"_ctv);

  EXPECT_EQ(suite, Filesystem::openWriteAtClose(subdirFd, payloadName, "tiny"_ctv), int("tiny"_ctv.size()));
  String overwritten;
  Filesystem::openReadAtClose(subdirFd, payloadName, overwritten);
  EXPECT_STRING_EQ(suite, overwritten, "tiny"_ctv);

  std::string oldPath = joinPath(tempDirectory.path(), "subdir/payload.txt");
  std::string newPath = joinPath(tempDirectory.path(), "subdir/renamed.txt");
  EXPECT_EQ(suite, Filesystem::renameFile(String(oldPath.c_str()), String(newPath.c_str())), 0);

  String renamed;
  Filesystem::openReadAtClose(subdirFd, "renamed.txt"_ctv, renamed);
  EXPECT_STRING_EQ(suite, renamed, "tiny"_ctv);
  EXPECT_STRING_EQ(suite, Filesystem::filenameFromPath(String(newPath.c_str())), "renamed.txt"_ctv);
  EXPECT_STRING_EQ(suite, Filesystem::filenameFromPath(String("plain.txt")), "plain.txt"_ctv);

  int safeFd = Filesystem::openFileAt(subdirFd, String("renamed.txt"), O_RDONLY | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS);
  EXPECT_TRUE(suite, safeFd >= 0);
  if (safeFd >= 0)
  {
    close(safeFd);
  }

  EXPECT_EQ(suite, Filesystem::openWriteAtClose(rootFd, "outside.txt"_ctv, "outside"_ctv), int("outside"_ctv.size()));
  EXPECT_EQ(suite, symlinkat("../outside.txt", subdirFd, "escape"), 0);

  errno = 0;
  int escapedFd = Filesystem::openFileAt(subdirFd, "escape"_ctv, O_RDONLY | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS);
  EXPECT_TRUE(suite, escapedFd < 0);
  if (escapedFd >= 0)
  {
    close(escapedFd);
  }

  close(subdirFd);
  close(rootFd);
}

static void testPartialReadAndPrimitiveIO(TestSuite& suite, bool& skipped)
{
  TempDirectory tempDirectory;
  int rootFd = openRootDirectory(suite, tempDirectory);
  if (rootFd == -2)
  {
    skipped = true;
    return;
  }
  if (rootFd < 0)
  {
    return;
  }

  EXPECT_EQ(suite, Filesystem::openWriteAtClose(rootFd, "bytes.bin"_ctv, "ABCDEFGHIJ"_ctv), int("ABCDEFGHIJ"_ctv.size()));

  String prefix;
  Filesystem::openReadAtClose(rootFd, "bytes.bin"_ctv, prefix, 4);
  EXPECT_STRING_EQ(suite, prefix, "ABCD"_ctv);

  String oversize;
  Filesystem::openReadAtClose(rootFd, "bytes.bin"_ctv, oversize, 64);
  EXPECT_STRING_EQ(suite, oversize, "ABCDEFGHIJ"_ctv);

  std::string primitivePath = joinPath(tempDirectory.path(), "value.bin");
  Filesystem::createFile(-1, String(primitivePath.c_str()));
  constexpr uint32_t kPrimitive = 0x01020304u;
  Filesystem::writePrimitive<uint32_t>(String(primitivePath.c_str()), kPrimitive);
  EXPECT_EQ(suite, Filesystem::readPrimitive<uint32_t>(String(primitivePath.c_str())), kPrimitive);

  EXPECT_EQ(suite, Filesystem::openWriteAtClose(rootFd, "short.bin"_ctv, "A"_ctv), int("A"_ctv.size()));
  std::string shortPath = joinPath(tempDirectory.path(), "short.bin");
  EXPECT_EQ(suite, Filesystem::readPrimitive<uint32_t>(String(shortPath.c_str())), uint32_t(0));

  close(rootFd);
}

static void testEraseDirectoryHandlesBrokenSymlink(TestSuite& suite, bool& skipped)
{
  TempDirectory tempDirectory;
  int rootFd = openRootDirectory(suite, tempDirectory);
  if (rootFd == -2)
  {
    skipped = true;
    return;
  }
  if (rootFd < 0)
  {
    return;
  }

  int subdirFd = Filesystem::createOpenDirectoryAt(rootFd, "subdir"_ctv);
  EXPECT_TRUE(suite, subdirFd >= 0);
  if (subdirFd < 0)
  {
    close(rootFd);
    return;
  }

  EXPECT_EQ(suite, Filesystem::openWriteAtClose(rootFd, "outside.txt"_ctv, "outside"_ctv), int("outside"_ctv.size()));
  EXPECT_EQ(suite, symlinkat("../outside.txt", subdirFd, "escape"), 0);

  std::string outsidePath = joinPath(tempDirectory.path(), "outside.txt");
  EXPECT_EQ(suite, unlink(outsidePath.c_str()), 0);

  close(subdirFd);
  close(rootFd);

  EXPECT_EQ(suite, Filesystem::eraseDirectory(String(tempDirectory.path())), 0);
  tempDirectory.release();
  EXPECT_TRUE(suite, access(tempDirectory.path(), F_OK) != 0);
}

} // namespace

int main()
{
  TestSuite suite;
  bool skipped = false;

  testCreateOpenReadWriteRename(suite, skipped);
  testPartialReadAndPrimitiveIO(suite, skipped);
  testEraseDirectoryHandlesBrokenSymlink(suite, skipped);

  if (skipped)
  {
    return 0;
  }

  return suite.finish("filesystem tests");
}
