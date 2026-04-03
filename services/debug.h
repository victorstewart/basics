// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <inttypes.h>
#include <type_traits>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <thread>

#pragma once

static void nonreorderable_sleep_ms(uint32_t ms)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  std::atomic_signal_fence(std::memory_order_acq_rel);
}

static void nonreorderable_sleep_us(uint32_t us)
{
  std::this_thread::sleep_for(std::chrono::microseconds(us));
  std::atomic_signal_fence(std::memory_order_acq_rel);
}

#if BASICS_DEBUG

#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <errno.h>

namespace LogImpl {

static sem_t *ipc_lock = [](void) -> sem_t * {
  int result;

  result = sem_unlink("/ipc_lock");

  sem_t *sem = sem_open("/ipc_lock", O_CREAT, 0644, 1);

  return sem;
}();

static sem_t *resolve_ipc_lock(void)
{
  if (ipc_lock != nullptr && ipc_lock != SEM_FAILED)
  {
    return ipc_lock;
  }

  sem_t *sem = sem_open("/ipc_lock", O_CREAT, 0644, 1);
  if (sem != SEM_FAILED)
  {
    ipc_lock = sem;
    return ipc_lock;
  }

  return nullptr;
}

template <typename Lambda>
static void ipc_guard(Lambda&& lambda)
{
  sem_t *sem = resolve_ipc_lock();
  if (sem == nullptr)
  {
    lambda();
    return;
  }

  while (sem_wait(sem) != 0)
  {
    if (errno != EINTR)
    {
      lambda();
      return;
    }
  }

  lambda();
  sem_post(sem);
}

}; // namespace LogImpl
#endif

template <int N>
bool is_aligned(void *p)
{
  return (int64_t)p % N == 0;
}

#define ENABLEIF_VOID(x) typename std::enable_if<(x), void>::type

template <typename... Args>
static void basics_log(Args&&...args)
{
#if BASICS_DEBUG

  LogImpl::ipc_guard([&](void) -> void {
    printf(args...);
  });

#endif
}

static void basics_log_hex8Byte(const char *name, uint64_t number)
{
  basics_log("%s -> 0x%" PRIx64 "\n", name, number);
}

static void basics_log_hex(const char *name, const uint8_t *start, uint32_t length)
{
#if BASICS_DEBUG

  LogImpl::ipc_guard([&](void) -> void {
    printf("%s -> ", name);

    if (length == 0)
    {
      printf("hex LENGTH == 0\n");
      return;
    }

    if (length > 300 * 1024)
    {
      printf("hex LENGTH > 300KB\n");
      return;
    }

    for (int i = 0; i < length; i++)
    {
      if (i > 0)
      {
        printf(":");
      }
      printf("%02x", start[i]);
    }

    printf("\n");
  });

#endif
}

template <typename T>
static ENABLEIF_VOID(std::is_integral_v<std::remove_reference_t<T>> || sizeof(T) == 16) basics_log_hex(const char *name, T&& integral)
{
  basics_log_hex(name, (uint8_t *)&integral, sizeof(T));
}

template <typename T>
static ENABLEIF_VOID(std::is_integral_v<std::remove_reference_t<T>> || std::is_enum_v<std::remove_reference_t<T>> || sizeof(T) == 16) basics_log_bits(const char *name, T&& integral)
{
#if BASICS_DEBUG

  LogImpl::ipc_guard([&](void) -> void {
    do
    {
      typeof(integral) a__ = (integral);
      char *p__ = (char *)&a__ + sizeof(integral) - 1;
      size_t bytes__ = sizeof(integral);

      printf("%s -> \t", name);

      while (bytes__--)
      {
        char bits__ = __CHAR_BIT__;
        while (bits__--)
        {
          putchar(*p__ & (1 << bits__) ? '1' : '0');
        }
        p__--;
      }

      putchar('\n');

    } while (0);
  });

#endif
}

static void printWorkingDirectory(void)
{
  char cwd[PATH_MAX];

  if (getcwd(cwd, sizeof(cwd)) != NULL)
  {
    basics_log("Current working directory: %s\n", cwd);
  }
  else
  {
    basics_log("getcwd() error\n");
  }
}

template <typename T>
static void printAlignment(const char *header, T *pointer)
{
  intptr_t& value = reinterpret_cast<intptr_t&>(pointer);

  uint8_t alignment;

  if ((value % 16) == 0)
  {
    alignment = 16;
  }
  else if ((value % 8) == 0)
  {
    alignment = 8;
  }
  else if ((value % 4) == 0)
  {
    alignment = 4;
  }
  else if ((value % 2) == 0)
  {
    alignment = 2;
  }
  else
  {
    alignment = 1;
  }

  basics_log("%s -> %hhu\n", header, alignment);
}
