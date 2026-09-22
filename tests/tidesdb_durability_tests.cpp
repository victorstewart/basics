// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "databases/embedded/tidesdb.h"
#include "services/filesystem.h"

namespace {

class TempDirectory {
private:

  std::array<char, 64> path_ {};
  bool valid_ = false;

public:

  TempDirectory()
  {
    std::snprintf(path_.data(), path_.size(), "/tmp/basics-tidesdb-durability-XXXXXX");
    valid_ = mkdtemp(path_.data()) != nullptr;
  }

  ~TempDirectory()
  {
    if (valid_)
    {
      Filesystem::eraseDirectory(String(path_.data()));
    }
  }

  bool valid(void) const
  {
    return valid_;
  }

  const char *path(void) const
  {
    return path_.data();
  }
};

#if defined(__linux__)
static bool liveWalFlags(
    const char *dbPath,
    unsigned long long& flags)
{
  std::string walPrefix(dbPath);
  // TidesDB 10 stores the shared, numerically named WAL at the database root.
  walPrefix.append("/");

  DIR *fds = opendir("/proc/self/fd");
  if (fds == nullptr)
  {
    return false;
  }

  bool found = false;
  while (dirent *entry = readdir(fds))
  {
    char *end = nullptr;
    errno = 0;
    long descriptor = std::strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' || descriptor < 0)
    {
      continue;
    }

    std::string descriptorPath = "/proc/self/fd/" + std::to_string(descriptor);
    std::array<char, PATH_MAX + 1> target {};
    ssize_t targetLength = readlink(descriptorPath.c_str(), target.data(), PATH_MAX);
    if (targetLength < 0)
    {
      continue;
    }
    std::string_view targetPath(target.data(), size_t(targetLength));
    if (targetPath.starts_with(walPrefix) == false || targetPath.ends_with(".log") == false ||
        targetPath.substr(walPrefix.size()).find('/') != std::string_view::npos)
    {
      continue;
    }

    std::string fdinfoPath = "/proc/self/fdinfo/" + std::to_string(descriptor);
    FILE *fdinfo = std::fopen(fdinfoPath.c_str(), "r");
    if (fdinfo == nullptr)
    {
      continue;
    }
    std::array<char, 256> line {};
    while (std::fgets(line.data(), line.size(), fdinfo))
    {
      if (std::strncmp(line.data(), "flags:", 6) == 0)
      {
        flags = std::strtoull(line.data() + 6, nullptr, 8);
        found = true;
        break;
      }
    }
    std::fclose(fdinfo);
    if (found)
    {
      break;
    }
  }

  closedir(fds);
  return found;
}

static size_t directoryEntryCountWithSuffix(
    const char *path,
    std::string_view suffix)
{
  DIR *directory = opendir(path);
  if (directory == nullptr)
  {
    return 0;
  }

  size_t count = 0;
  while (dirent *entry = readdir(directory))
  {
    std::string_view name(entry->d_name);
    if (name == "." || name == "..")
    {
      continue;
    }

    std::string entryPath(path);
    entryPath.append("/");
    entryPath.append(name);
    struct stat status {};
    if (lstat(entryPath.c_str(), &status) == 0 && S_ISDIR(status.st_mode))
    {
      count += directoryEntryCountWithSuffix(entryPath.c_str(), suffix);
      continue;
    }

    if (name.ends_with(suffix))
    {
      ++count;
    }
  }

  closedir(directory);
  return count;
}
#endif

} // namespace

int main()
{
#if !defined(__linux__)
  std::puts("tidesdb durability tests skipped: Linux /proc fd flags required");
  return 0;
#else
  TestSuite suite;
  TempDirectory tempDirectory;
  EXPECT_TRUE(suite, tempDirectory.valid());
  if (tempDirectory.valid() == false)
  {
    return suite.finish("tidesdb durability tests");
  }

  String failure;
  {
    TidesDB db(String(tempDirectory.path()), TidesDB::Durability::inherit);
    EXPECT_TRUE(suite, db.write("existing"_ctv, "key"_ctv, "seed"_ctv, &failure));
    unsigned long long flags = 0;
    EXPECT_TRUE(suite, liveWalFlags(tempDirectory.path(), flags));
    EXPECT_FALSE(suite, (flags & O_DSYNC) != 0);
  }

  {
    TidesDB db(String(tempDirectory.path()), TidesDB::Durability::full);
    String value;
    EXPECT_TRUE(suite, db.read("existing"_ctv, "key"_ctv, value, &failure));
    EXPECT_TRUE(suite, value == "seed"_ctv);
    failure.clear();
    EXPECT_TRUE(suite, db.write("existing"_ctv, "key"_ctv, "promoted"_ctv, &failure));
    unsigned long long promotedFlags = 0;
    EXPECT_TRUE(suite, liveWalFlags(tempDirectory.path(), promotedFlags));
    EXPECT_TRUE(suite, (promotedFlags & O_DSYNC) != 0);

    failure.clear();
    EXPECT_TRUE(suite, db.write("new-full"_ctv, "key"_ctv, "created"_ctv, &failure));
    unsigned long long createdFlags = 0;
    EXPECT_TRUE(suite, liveWalFlags(tempDirectory.path(), createdFlags));
    EXPECT_TRUE(suite, (createdFlags & O_DSYNC) != 0);
  }

  {
    TidesDB db(String(tempDirectory.path()), TidesDB::Durability::full);
    String value;
    EXPECT_TRUE(suite, db.read("existing"_ctv, "key"_ctv, value, &failure));
    EXPECT_TRUE(suite, value == "promoted"_ctv);
    EXPECT_TRUE(suite, db.read("new-full"_ctv, "key"_ctv, value, &failure));
    EXPECT_TRUE(suite, value == "created"_ctv);
    Vector<String> values;
    EXPECT_TRUE(suite, db.listValues("new-full"_ctv, values, &failure));
    EXPECT_TRUE(suite, values.size() == 1);
    if (values.size() == 1)
    {
      EXPECT_TRUE(suite, values[0] == "created"_ctv);
    }
    EXPECT_TRUE(suite, db.remove("new-full"_ctv, "key"_ctv, &failure));
  }
  {
    TidesDB db(String(tempDirectory.path()), TidesDB::Durability::full);
    String value;
    EXPECT_FALSE(suite, db.read("new-full"_ctv, "key"_ctv, value, &failure));
    EXPECT_TRUE(suite, failure == "record not found"_ctv);
    EXPECT_TRUE(suite, db.read("existing"_ctv, "key"_ctv, value, &failure));
    EXPECT_TRUE(suite, value == "promoted"_ctv);
  }

  TempDirectory recoveredFlushDirectory;
  EXPECT_TRUE(suite, recoveredFlushDirectory.valid());
  if (recoveredFlushDirectory.valid())
  {
    pid_t child = fork();
    EXPECT_TRUE(suite, child >= 0);
    if (child == 0)
    {
      TidesDB db(
          String(recoveredFlushDirectory.path()),
          TidesDB::Durability::full);
      String childFailure;
      _exit(db.write("recovered"_ctv, "prior"_ctv, "before-reopen"_ctv, &childFailure) ? 0 : 1);
    }
    if (child > 0)
    {
      int status = 0;
      EXPECT_TRUE(suite, waitpid(child, &status, 0) == child);
      EXPECT_TRUE(suite, WIFEXITED(status));
      EXPECT_TRUE(suite, WEXITSTATUS(status) == 0);
      EXPECT_TRUE(suite, directoryEntryCountWithSuffix(recoveredFlushDirectory.path(), ".klog") == 0);

      TidesDB db(
          String(recoveredFlushDirectory.path()),
          TidesDB::Durability::full,
          64 * 1024);
      EXPECT_TRUE(suite, db.write("recovered"_ctv, "next"_ctv, "after-reopen"_ctv, &failure));
      EXPECT_TRUE(suite, directoryEntryCountWithSuffix(recoveredFlushDirectory.path(), ".klog") > 0);
      String readback;
      EXPECT_TRUE(suite, db.read("recovered"_ctv, "prior"_ctv, readback, &failure));
      EXPECT_TRUE(suite, readback == "before-reopen"_ctv);
      EXPECT_TRUE(suite, db.read("recovered"_ctv, "next"_ctv, readback, &failure));
      EXPECT_TRUE(suite, readback == "after-reopen"_ctv);
    }
  }

  return suite.finish("tidesdb durability tests");
#endif
}
