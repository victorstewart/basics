// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#pragma once

class Memfd {
private:

  template <size_t N>
  static const char *nameCString(const char (&name)[N], String&)
  {
    (void)N;
    return name;
  }

  static const char *nameCString(const char *name, String&)
  {
    return (name == nullptr) ? "" : name;
  }

  static const char *nameCString(StringType auto&& name, String& scratch)
  {
    scratch.clear();
    scratch.append(name.data(), name.size());
    scratch.addNullTerminator();
    return reinterpret_cast<const char *>(scratch.data());
  }

public:

  static int create(const char *name)
  {
    String scratch;
    // flags = 0 to ensure FD is inherited across exec (no CLOEXEC)
    return int(syscall(SYS_memfd_create, nameCString(name, scratch), 0));
  }

  static int create(StringType auto&& name)
  {
    String scratch;
    // flags = 0 to ensure FD is inherited across exec (no CLOEXEC)
    return int(syscall(SYS_memfd_create, nameCString(name, scratch), 0));
  }

  static bool writeAll(int fd, StringType auto&& data)
  {
    if (fd < 0)
    {
      return false;
    }

    uint64_t written = 0;
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(data.data());
    uint64_t remaining = data.size();
    while (remaining > 0)
    {
      ssize_t chunk = ::write(fd, bytes + written, remaining);
      if (chunk <= 0)
      {
        return false;
      }

      written += uint64_t(chunk);
      remaining -= uint64_t(chunk);
    }

    return true;
  }

  static bool readAll(int fd, String& out)
  {
    if (fd < 0)
    {
      return false;
    }

    struct stat64 statBuffer = {};
    if (fstat64(fd, &statBuffer) != 0 || statBuffer.st_size <= 0)
    {
      return false;
    }

    // Callers may pass inherited memfds that were just written before exec.
    // Rewind so reads are deterministic regardless of the current offset.
    if (lseek(fd, 0, SEEK_SET) < 0)
    {
      return false;
    }

    uint64_t totalBytes = uint64_t(statBuffer.st_size);

    out.clear();
    if (out.reserve(totalBytes) == false)
    {
      return false;
    }

    uint64_t totalRead = 0;
    while (totalRead < totalBytes)
    {
      ssize_t chunk = ::read(fd, out.pTail() + totalRead, totalBytes - totalRead);
      if (chunk <= 0)
      {
        out.clear();
        return false;
      }

      totalRead += uint64_t(chunk);
    }

    out.advance(totalRead);
    return true;
  }

  static bool dupTo(int fd, int fixedFd)
  {
    if (fd < 0 || fixedFd < 0)
    {
      return false;
    }

    // duplicate to a fixed, known fd number for discovery after exec
    return (dup3(fd, fixedFd, 0) == fixedFd);
  }
};
