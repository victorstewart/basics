// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <cstdint>

#pragma once

static uint8_t alignmentOfAddress(uint8_t *pointer)
{
  uintptr_t value = reinterpret_cast<uintptr_t>(pointer);

  if ((value % 16) == 0)
  {
    return 16;
  }
  else if ((value % 8) == 0)
  {
    return 8;
  }
  else if ((value % 4) == 0)
  {
    return 4;
  }
  else if ((value % 2) == 0)
  {
    return 2;
  }
  else
  {
    return 1;
  }
}

template <Alignment alignment, typename T>
static void align(T& pointer)
{
  if constexpr (alignment > Alignment::one)
  {
    uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
    value += (-value) & ((uint64_t)alignment - 1);
    pointer = reinterpret_cast<T>(value);
  }
}

template <typename T>
static void align(Alignment alignment, T& pointer)
{
  if (alignment > Alignment::one)
  {
    uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
    value += (-value) & ((uint64_t)alignment - 1);
    pointer = reinterpret_cast<T>(value);
  }
}

static uint8_t shiftRequiredToAlign(uint8_t alignment, uint64_t offsetFromBufferStart) // assume the buffer starts 16 byte aligned
{
  int remainder = offsetFromBufferStart % 16;
  int additional_shift = 0;

  if (remainder > 0)
  {
    int current_alignment = remainder & -remainder;

    if (current_alignment < alignment)
    {
      // If the current alignment is smaller than m, we need to shift it more
      // to reach the next m boundary.
      return alignment - remainder % alignment;
    }

    // If the current alignment is equal or larger than m,
    // the pointer is already at least m-byte aligned, so no additional shift is necessary.
  }

  return 0;
}
