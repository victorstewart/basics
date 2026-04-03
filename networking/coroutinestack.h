// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <vector>
#include <coroutine>
#include <optional>
#include <source_location>
#include <type_traits>
#include <utility>

#pragma once

using std::coroutine_handle;
using std::suspend_always;
using std::suspend_never;

template <typename T>
struct task_promise;

template <>
struct task_promise<void> {

  auto initial_suspend()
  {
    return std::suspend_never {};
  }
  auto final_suspend() noexcept
  {
    return std::suspend_never {};
  }
  void unhandled_exception() {}
  void return_void() {}
  void get_return_object() {}
};

class CoroutineStack;

class Cotask {
public:

  CoroutineStack *stack;

  Cotask(CoroutineStack *_stack) noexcept
      : stack(_stack)
  {}

  bool await_ready(void)
  {
    return false;
  }
  bool await_suspend(coroutine_handle<task_promise<void>> handle);
  void await_resume(void) {}
};

class CoroutineStack {
public:

  Vector<coroutine_handle<>> suspended;
  Cotask awaiter;
  int32_t overrideIndex = -1;
  uint64_t suspensionGeneration = 0;

  bool hasSuspendedCoroutines(void)
  {
    return suspended.size() > 0;
  }

  void runNextSuspended(void)
  {
    auto handle = suspended.back(); // copy on purpose
    suspended.pop_back();

    handle.resume();
  }

  virtual void co_consume(void) // this can be overridden
  {
    while (hasSuspendedCoroutines())
    {
      if (didSuspend([&](void) -> void {
            runNextSuspended();
          }))
      {
        break; // stop once a coroutine blocks again
      }
    }
  }

  void cancelSuspended(void)
  {
    for (auto& coroutine : suspended)
    {
      coroutine.destroy();
    }

    suspended.clear();
  }

  virtual void reset(void)
  {
    cancelSuspended();
  }

  uint32_t nextSuspendIndex(void)
  {
    return suspended.size();
  }

  auto& suspend(void)
  {
    return awaiter;
  }

  auto& suspendAtIndex(uint32_t index)
  {
    overrideIndex = index;
    return awaiter;
  }

  template <typename Lambda>
  auto& suspendUsRunThis(Lambda&& lambda)
  {
    uint32_t suspendIndex = nextSuspendIndex();
    lambda();
    return suspendAtIndex(suspendIndex);
  }

  template <typename Lambda>
  bool didSuspend(Lambda&& lambda)
  {
    uint64_t generation = suspensionGeneration;
    lambda();
    return (generation != suspensionGeneration);
  }

  CoroutineStack()
      : awaiter(this)
  {
    // valgrind crashed on this saying new failed
    // suspended.reserve(10);
  }
};

namespace std {
template <typename... Args>
struct coroutine_traits<void, Args...> {
  using promise_type = task_promise<void>;
};
} // namespace std

inline __attribute__((noinline)) bool Cotask::await_suspend(coroutine_handle<task_promise<void>> handle)
{
  if (stack->overrideIndex != -1)
  {
    stack->suspended.insert(stack->suspended.begin() + stack->overrideIndex, handle);
    stack->overrideIndex = -1;
  }
  else
  {
    stack->suspended.push_back(handle);
  }

  ++stack->suspensionGeneration;

  return true;
}

template <typename T>
struct CoroutineGenerator {
  struct promise_type {
    // The most recently yielded value
    std::optional<T> currentValue;

    // Return the generator object
    CoroutineGenerator get_return_object()
    {
      return CoroutineGenerator {
          std::coroutine_handle<promise_type>::from_promise(*this)};
    }

    std::suspend_always initial_suspend()
    {
      return {};
    }
    std::suspend_always final_suspend() noexcept
    {
      return {};
    }

    // If an exception occurs, do nothing or terminate
    void unhandled_exception() {}

    void return_void() {}

    // Intercept co_await. If it's a Cotask, wrap it so we push
    // the *generator's* handle onto stack->suspended. Otherwise forward.
    template <typename Awaitable>
    auto await_transform(Awaitable&& awaitable)
    {
      // If it's exactly Cotask:
      if constexpr (std::is_same_v<std::decay_t<Awaitable>, Cotask>)
      {
        // We'll define a small adapter to push the generator handle
        struct AwaitableAdapter {
          Cotask& c;
          bool await_ready()
          {
            return c.await_ready();
          }
          bool await_suspend(std::coroutine_handle<promise_type> h)
          {
            // same logic as Cotask::await_suspend
            if (c.stack->overrideIndex != -1)
            {
              c.stack->suspended.insert(c.stack->suspended.begin() + c.stack->overrideIndex, h);
              c.stack->overrideIndex = -1;
            }
            else
            {
              c.stack->suspended.push_back(h);
            }
            ++c.stack->suspensionGeneration;
            return true;
          }
          void await_resume()
          {
            c.await_resume();
          }
        };

        return AwaitableAdapter {awaitable};
      }
      else
      {
        // Otherwise pass it through
        return std::forward<Awaitable>(awaitable);
      }
    }

    // Called when we do: co_yield <value>
    std::suspend_always yield_value(T value)
    {
      currentValue = std::move(value);
      return {};
    }
  };

  // Provide an iterator for range-based for
  struct iterator {
    std::coroutine_handle<promise_type> coro = nullptr;
    bool done = false;

    iterator& operator++()
    {
      coro.resume();
      if (coro.done())
      {
        done = true;
      }
      return *this;
    }

    const T& operator*() const
    {
      return *coro.promise().currentValue;
    }

    const T *operator->() const
    {
      return &*coro.promise().currentValue;
    }

    bool operator==(std::default_sentinel_t) const
    {
      return done;
    }
  };

  iterator begin()
  {
    if (coro)
    {
      coro.resume();
      if (coro.done())
      {
        finished_ = true;
      }
    }

    return {coro, finished_};
  }

  std::default_sentinel_t end()
  {
    return {};
  }

  // Clean up the coroutine if not finished
  ~CoroutineGenerator()
  {
    if (coro)
    {
      coro.destroy();
    }
  }

  // Move-only
  CoroutineGenerator(CoroutineGenerator&& other) noexcept
      : coro(other.coro),
        finished_(other.finished_)
  {
    other.coro = nullptr;
    other.finished_ = true;
  }

  CoroutineGenerator& operator=(CoroutineGenerator&& other) noexcept
  {
    if (this != &other)
    {
      if (coro)
      {
        coro.destroy();
      }
      coro = other.coro;
      finished_ = other.finished_;
      other.coro = nullptr;
      other.finished_ = true;
    }

    return *this;
  }

private:

  std::coroutine_handle<promise_type> coro;
  bool finished_ = false;

  explicit CoroutineGenerator(std::coroutine_handle<promise_type> h)
      : coro(h)
  {}
};

// Hook CoroutineGenerator<T> into std::coroutine_traits
namespace std {
template <typename T, typename... Args>
struct coroutine_traits<CoroutineGenerator<T>, Args...> {
  using promise_type = typename CoroutineGenerator<T>::promise_type;
};
} // namespace std
