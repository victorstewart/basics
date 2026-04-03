// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <memory>

typedef uint64_t Tick;

class TimerWheelSlot;
class TimerWheel;

// An abstract class representing an event that can be scheduled to
// happen at some later time.
class TimerEventInterface {
public:

  TimerEventInterface() = default;

  // TimerEvents are automatically canceled on destruction.
  virtual ~TimerEventInterface()
  {
    cancel();
  }

  // Unschedule this event. It's safe to cancel an event that is inactive.
  inline void cancel()
  {
    // It's ok to cancel a event that's not scheduled.
    if (!slot_)
    {
      return;
    }

    relink(NULL);
  }

  // Return true if the event is currently scheduled for execution.
  bool active() const
  {
    return slot_ != NULL;
  }

  // Return the absolute tick this event is scheduled to be executed on.
  Tick scheduled_at() const
  {
    return scheduled_at_;
  }

private:

  TimerEventInterface(const TimerEventInterface& other) = delete;
  TimerEventInterface& operator=(const TimerEventInterface& other) = delete;
  friend TimerWheelSlot;
  friend TimerWheel;

  // Implement in subclasses. Executes the event callback.
  virtual void execute() = 0;

  void set_scheduled_at(Tick ts)
  {
    scheduled_at_ = ts;
  }
  // Move the event to another slot. (It's safe for either the current
  // or new slot to be NULL).

  void relink(TimerWheelSlot *slot);

  Tick scheduled_at_ = 0;
  // The slot this event is currently in (NULL if not currently scheduled).
  TimerWheelSlot *slot_ = NULL;
  // The events are linked together in the slot using an internal
  // doubly-linked list; this iterator does double duty as the
  // linked list node for this event.
  TimerEventInterface *next_ = NULL;
  TimerEventInterface *prev_ = NULL;
};

// Purely an implementation detail.
class TimerWheelSlot {
public:

  TimerWheelSlot() {}

private:

  // Return the first event queued in this slot.
  const TimerEventInterface *events() const
  {
    return events_;
  }
  // Deque the first event from the slot, and return it.
  TimerEventInterface *pop_event()
  {
    auto event = events_;
    events_ = event->next_;
    if (events_)
    {
      events_->prev_ = NULL;
    }

    event->next_ = NULL;
    event->slot_ = NULL;

    return event;
  }

  TimerWheelSlot(const TimerWheelSlot& other) = delete;
  TimerWheelSlot& operator=(const TimerWheelSlot& other) = delete;
  friend TimerEventInterface;
  friend TimerWheel;

  // Doubly linked (inferior) list of events.
  TimerEventInterface *events_ = NULL;
};

// A TimerWheel is the entity that TimerEvents can be scheduled on
// for execution (with schedule() or schedule_in_range()), and will
// eventually be executed once the time advances far enough with the
// advance() method.
class TimerWheel {
public:

  TimerWheel(Tick now = 0)
  {
    for (int i = 0; i < NUM_LEVELS; ++i)
    {
      now_[i] = now >> (WIDTH_BITS * i); // largest times are lower levels
    }
  }

  // Schedule the event to be executed delta ticks from the current time.
  // The delta must be non-0.
  inline void schedule(TimerEventInterface *event, Tick delta)
  {
    if (delta == 0)
    {
      delta = 1;
    }

    event->set_scheduled_at(now_[0] + delta);

    int level = 0;

    while (delta >= NUM_SLOTS && level < (NUM_LEVELS - 1))
    {
      delta = (delta + (now_[level] & MASK)) >> WIDTH_BITS;
      ++level;
    }

    size_t slot_index = (now_[level] + delta) & MASK;

    auto slot = &(slots_[level][slot_index]);

    event->relink(slot);
  }

  // Return the current tick value. Note that if the time increases
  // by multiple ticks during a single call to advance(), during the
  // execution of the event callback now() will return the tick that
  // the event was scheduled to run on.
  Tick now() const
  {
    return now_[0];
  }

  // Return the number of ticks remaining until the next event will get
  // executed. If the max parameter is passed, that will be the maximum
  // tick value that gets returned. The max parameter's value will also
  // be returned if no events have been scheduled.
  //
  // Will return 0 if the wheel still has unprocessed events from the
  // previous call to advance().
  inline Tick ticks_to_next_event(void)
  {
    Tick max = oneDayInMilliseconds; // one day in milliseconds
    int level = 0;

    do
    {
      // The actual current time (not the bitshifted time)
      Tick now = now_[0];

      // Smallest tick (relative to now) we've found.
      Tick min = max;

      for (int i = 0; i < NUM_SLOTS; ++i)
      {
        // Note: Unlike the uses of "now", slot index calculations really
        // need to use now_.
        auto slot_index = (now_[level] + 1 + i) & MASK;

        // We've reached slot 0. In normal scheduling this would
        // mean advancing the next wheel and promoting or executing
        // those events.  So we need to look in that slot too
        // before proceeding with the rest of this wheel. But we
        // can't just accept those results outright, we need to
        // check the best result there against the next slot on
        // this wheel.
        if (slot_index == 0 && level < MAX_LEVEL)
        {
          // Exception: If we're in the core wheel, and slot 0 is
          // not empty, there's no point in looking in the outer wheel.
          // It's guaranteed that the events actually in slot 0 will be
          // executed no later than anything in the outer wheel.
          if (level > 0 || !slots_[level][slot_index].events())
          {
            auto up_slot_index = (now_[level + 1] + 1) & MASK;
            const auto& slot = slots_[level + 1][up_slot_index];

            for (auto event = slot.events(); event != NULL; event = event->next_)
            {
              min = std::min(min, event->scheduled_at() - now);
            }
          }
        }

        bool found = false;
        const auto& slot = slots_[level][slot_index];

        for (auto event = slot.events(); event != NULL; event = event->next_)
        {
          min = std::min(min, event->scheduled_at() - now);
          // In the core wheel all the events in a slot are guaranteed to
          // run at the same time, so it's enough to just look at the first
          // one.
          if (level == 0)
          {
            return min;
          }
          else
          {
            found = true;
          }
        }

        if (found)
        {
          return min;
        }
      }

      // Nothing found on this wheel, try the next one
      ++level;

    } while (level < MAX_LEVEL);

    return max;
  }

  bool advance(Tick delta, int level = 0)
  {
    while (delta--)
    {
      Tick now = ++now_[level];

      if (!process_current_slot(now, level))
      {
        return false;
      }
    }

    return true;
  }

  bool process_current_slot(Tick now, int level)
  {
    size_t slot_index = now & MASK;
    auto slot = &slots_[level][slot_index];

    if (slot_index == 0 && level < MAX_LEVEL)
    {
      if (!advance(1, level + 1))
      {
        return false;
      }
    }

    while (slot->events())
    {
      auto event = slot->pop_event();

      if (level > 0)
      {
        // assert((now_[0] & MASK) == 0);
        if (now_[0] >= event->scheduled_at())
        {
          event->execute();
        }
        else
        {
          // There's a case to be made that promotion should
          // also count as work done. And that would simplify
          // this code since the max_events manipulation could
          // move to the top of the loop. But it's an order of
          // magnitude more expensive to execute a typical
          // callback, and promotions will naturally clump while
          // events triggering won't.
          schedule(event, event->scheduled_at() - now_[0]);
        }
      }
      else
      {
        event->execute();
      }
    }

    return true;
  }

private:

  TimerWheel(const TimerWheel& other) = delete;
  TimerWheel& operator=(const TimerWheel& other) = delete;

  // our timeouts will never be beyond 24 hours... and we use milliseconds

  static const int WIDTH_BITS = 8;
  static const int NUM_LEVELS = (64 + WIDTH_BITS - 1) / WIDTH_BITS; // 8
  static const int MAX_LEVEL = NUM_LEVELS - 1; // 7
  static const int NUM_SLOTS = 1 << WIDTH_BITS; // 256

  // A bitmask for looking at just the bits in the timestamp relevant to
  // this wheel.
  static const int MASK = (NUM_SLOTS - 1);

  // The current timestamp for this wheel. This will be right-shifted
  // such that each slot is separated by exactly one tick even on
  // the outermost wheels.
  Tick now_[NUM_LEVELS];
  TimerWheelSlot slots_[NUM_LEVELS][NUM_SLOTS];
};

void TimerEventInterface::relink(TimerWheelSlot *new_slot)
{
  if (new_slot == slot_)
  {
    return;
  }

  // Unlink from old location.
  if (slot_)
  {
    auto prev = prev_;
    auto next = next_;

    if (next)
    {
      next->prev_ = prev;
    }

    if (prev)
    {
      prev->next_ = next;
    }
    // Must be at head of slot. Move the next item to the head.
    else
    {
      slot_->events_ = next;
    }
  }

  // Insert in new slot.
  if (new_slot)
  {
    auto oldHead = new_slot->events_;

    next_ = oldHead;

    if (oldHead)
    {
      oldHead->prev_ = this;
    }

    new_slot->events_ = this;
  }
  else
  {
    next_ = NULL;
  }

  prev_ = NULL;

  slot_ = new_slot;
}
