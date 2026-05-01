// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <pthread.h>

#pragma once

class Thread {
private:

  struct ThreadData {

    std::function<void()> lambda;
  };

  static void *thread_trampoline(void *arg)
  {
    // block all signals
    sigset_t signal_set;
    sigfillset(&signal_set);
    // Keep synchronous fault signals unmasked so process/global crash handlers
    // can produce diagnostics (for example /crashreport.txt backtraces).
    sigdelset(&signal_set, SIGSEGV);
    sigdelset(&signal_set, SIGBUS);
    sigdelset(&signal_set, SIGABRT);
    sigdelset(&signal_set, SIGILL);
    sigdelset(&signal_set, SIGFPE);
    pthread_sigmask(SIG_BLOCK, &signal_set, nullptr);

    ThreadData *data = static_cast<ThreadData *>(arg);
    data->lambda();
    delete data;

    return nullptr;
  }

public:

  template <typename Lambda> requires (std::invocable<Lambda> && std::same_as<std::invoke_result_t<Lambda>, void>) // no arguments + returns void
  static bool startDetachedOnCore(uint32_t logicalCoreNumber, Lambda&& lambda)
  {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(logicalCoreNumber, &cpuset);

    pthread_t thread;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ThreadData *data = new ThreadData;
    data->lambda = std::move(lambda);

    int rc = pthread_create(&thread, &attr, thread_trampoline, data);

    pthread_attr_destroy(&attr);

    if (rc == 0)
    {
      return true;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    rc = pthread_create(&thread, &attr, thread_trampoline, data);

    pthread_attr_destroy(&attr);

    if (rc == 0)
    {
      return true;
    }

    delete data;
    return false;
  }

  static bool pinThisThreadToCore(int core)
  {
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(core, &cpuSet);

    return sched_setaffinity(0, sizeof(cpuSet), &cpuSet) == 0;
  }
};

#include <shared_mutex>

template <typename Key, typename Value>
class bytell_hash_map_shared : public bytell_hash_map_with_policy<Key, Value, Hasher::SeedPolicy::global_shared> {
public:

  std::shared_mutex mtx;
};

template <typename Key>
class bytell_hash_set_shared : public bytell_hash_set_with_policy<Key, Hasher::SeedPolicy::global_shared> {
public:

  std::shared_mutex mtx;
};
