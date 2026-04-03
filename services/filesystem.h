// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h> // fstat64
#include <fcntl.h> /* Definition of O_* and S_* constants */
#include <linux/openat2.h> /* Definition of RESOLVE_* constants */
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <dirent.h>

#pragma once

class Filesystem {
private:

  static int normalizeDirFD(int parentDirFD)
  {
    return (parentDirFD == -1) ? AT_FDCWD : parentDirFD;
  }

  static const char *pathCString(const char *path, String&)
  {
    return path;
  }

  template <size_t N>
  static const char *pathCString(const char (&path)[N], String&)
  {
    (void)N;
    return path;
  }

  static const char *pathCString(StringType auto&& path, String& scratch)
  {
    scratch.clear();
    scratch.append(path.data(), path.size());
    scratch.addNullTerminator();
    return reinterpret_cast<const char *>(scratch.data());
  }

  static uint64_t fileSize(int fd)
  {
    if (fd < 0)
    {
      return 0;
    }

    struct stat64 statbuf;
    if (fstat64(fd, &statbuf) != 0)
    {
      return 0;
    }

    return uint64_t(statbuf.st_size);
  }

public:

  static uint64_t fileSize(StringType auto&& filepath)
  {
    int fd = openFileAt(-1, filepath, O_RDONLY);

    uint64_t nBytes = fileSize(fd);

    close(fd);

    return nBytes;
  }

  static uint64_t directorySize(const char *path)
  {
    struct stat64 statbuf;
    stat64(path, &statbuf);

    return statbuf.st_size;
  }

  static int createDirectoryAt(int parentDirFD, StringType auto&& path, int flags = S_IRWXU)
  {
    String scratch;
    return mkdirat(normalizeDirFD(parentDirFD), pathCString(path, scratch), flags);
  }

  static int openDirectoryAt(int parentDirFD, StringType auto&& relativeFilepath, int flags = O_PATH | O_DIRECTORY | O_CLOEXEC, uint64_t resolveFlags = 0)
  {
    struct open_how how;
    memset(&how, 0, sizeof(how));

    how.flags = flags;
    how.resolve = resolveFlags;
    String scratch;
    return syscall(SYS_openat2, normalizeDirFD(parentDirFD), pathCString(relativeFilepath, scratch), &how, sizeof(struct open_how));
  }

  static int createOpenDirectoryAt(int parentDirFD, StringType auto&& path, int createFlags = S_IRWXU, int openFlags = O_PATH | O_DIRECTORY | O_CLOEXEC, uint64_t resolveFlags = 0)
  {
    createDirectoryAt(parentDirFD, path, createFlags);
    return openDirectoryAt(parentDirFD, path, openFlags, resolveFlags);
  }

  static int renameFile(StringType auto&& oldpath, StringType auto&& newpath)
  {
    String oldScratch;
    String newScratch;
    return syscall(SYS_renameat2, -1, pathCString(oldpath, oldScratch), -1, pathCString(newpath, newScratch), 0);
  }

  static int openFileAt(int parentDirFD, StringType auto&& relativeFilepath, int flags = O_RDONLY | O_CLOEXEC, int mode = 0, uint64_t resolveFlags = 0)
  {
    struct open_how how;
    memset(&how, 0, sizeof(how));

    how.flags = flags;
    how.mode = mode;
    how.resolve = resolveFlags;

    String scratch;
    return syscall(SYS_openat2, normalizeDirFD(parentDirFD), pathCString(relativeFilepath, scratch), &how, sizeof(struct open_how));
  }

  static String filenameFromPath(const String& filepath)
  {
    int32_t idx = filepath.rfindChar('/');
    if (idx == -1)
    {
      idx = 0;
    }
    else
    {
      idx += 1;
    }

    return filepath.substr(idx, filepath.size() - idx, Copy::yes);
  }

  static int openWriteAtClose(int parentDirFD, StringType auto&& relativeFilepath, StringType auto&& payload)
  {
    int fd = openFileAt(parentDirFD, relativeFilepath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
      return -1;
    }

    int result = write(fd, payload.data(), payload.size());
    close(fd);

    return result;
  }

  static void makeFileExecutable(StringType auto&& filepath)
  {
    String scratch;
    chmod(pathCString(filepath, scratch), 0755);
  }

  static void openReadAtClose(int parentDirFD, StringType auto&& filepath, String& output, int64_t nBytesToRead = -1)
  {
    if (nBytesToRead == 0 || nBytesToRead < -1)
    {
      return;
    }

    int fd = openFileAt(parentDirFD, filepath, O_RDONLY);
    if (fd < 0)
    {
      return;
    }

    uint64_t requestedBytes = (nBytesToRead == -1) ? fileSize(fd) : uint64_t(nBytesToRead);
    if (requestedBytes > 0)
    {
      output.need(requestedBytes);
    }

    uint64_t totalRead = 0;
    while (true)
    {
      if (output.remainingCapacity() == 0)
      {
        uint64_t growBy = 4096;
        if (nBytesToRead != -1)
        {
          if (totalRead >= requestedBytes)
          {
            break;
          }

          growBy = std::min<uint64_t>(growBy, requestedBytes - totalRead);
        }

        if (output.need(growBy) == false)
        {
          break;
        }
      }

      size_t readSize = output.remainingCapacity();
      if (nBytesToRead != -1)
      {
        readSize = std::min<uint64_t>(readSize, requestedBytes - totalRead);
        if (readSize == 0)
        {
          break;
        }
      }

      ssize_t length = read(fd, output.pTail(), readSize);
      if (length <= 0)
      {
        break;
      }

      output.advance(length);
      totalRead += uint64_t(length);
    }

    close(fd);
  }

  template <typename Primitive, StringType T>
  static Primitive readPrimitive(T&& filepath)
  {
    String output;
    openReadAtClose(-1, std::forward<T>(filepath), output);
    return output.as<Primitive>();
  }

  template <typename Primitive, StringType T>
  static void writePrimitive(T&& filepath, Primitive primitive)
  {
    int fd = openFileAt(-1, filepath, O_WRONLY);
    int result = write(fd, (uint8_t *)&primitive, sizeof(Primitive));
    close(fd);
  }

  static void createFile(int parentDirFD, StringType auto&& filepath)
  {
    close(openFileAt(parentDirFD, filepath, O_CREAT, S_IRWXU));
  }

  static int eraseFile(StringType auto&& filepath)
  {
    String scratch;
    return unlink(pathCString(filepath, scratch));
  }

  template <typename Consumer>
  static void iterateOverDirectoryAtPath(StringType auto&& dirpath, Consumer&& consumer)
  {
    String scratch;
    DIR *dir = opendir(pathCString(dirpath, scratch));
    if (dir == nullptr)
    {
      return;
    }

    struct dirent *entry;
    String entry_name;

    while ((entry = readdir(dir)) != NULL)
    {
      if constexpr (std::is_invocable_v<decltype(consumer), struct dirent *>)
      {
        consumer(entry);
      }
      else
      {
        entry_name.setInvariant(entry->d_name, strlen(entry->d_name));

        if (entry_name == "."_ctv || entry_name == ".."_ctv)
        {
          continue;
        }

        if constexpr (std::is_same_v<std::invoke_result_t<decltype(consumer), String>, bool>)
        {
          if (consumer(entry_name) == false)
          {
            break;
          }
        }
        else
        {
          consumer(entry_name);
        }
      }
    }

    closedir(dir);
  }

  static int eraseDirectory(StringType auto&& dirpath)
  {
    String full_path;
    struct stat stat_entry;

    bool failed = false;

    iterateOverDirectoryAtPath(std::forward<decltype(dirpath)>(dirpath), [&](const String& entryName) -> bool {
      full_path.snprintf<"{}/{}"_ctv>(dirpath, entryName);
      if (lstat(full_path.c_str(), &stat_entry) != 0)
      {
        failed = true;
        return false;
      }

      // recursively remove a nested directory
      if (S_ISDIR(stat_entry.st_mode) != 0)
      {
        if (eraseDirectory(full_path) != 0)
        {
          failed = true;
          return false;
        }

        return true;
      }

      if (unlink(full_path.c_str()) != 0)
      {
        failed = true;
        return false;
      }

      return true;
    });

    String scratch;
    if (rmdir(pathCString(dirpath, scratch)) != 0)
    {
      return -1;
    }

    return failed ? -1 : 0;
  }

  static bool fileExists(StringType auto&& path)
  {
    String scratch;
    return (access(pathCString(path, scratch), F_OK) == 0);
  }

  static void close(int fd)
  {
    ::close(fd);
  }
};
