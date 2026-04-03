// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

template <typename T, bool allowOverflow = false, bool storeOutstanding = false>
class Pool {
private:

  uint32_t capacity = 0;
  uint32_t watermark = 0;

  T *base = nullptr;
  Vector<T *> available;
  bytell_hash_set<T *> *outstanding = nullptr;

  bool isBaseItem(const T *item) const
  {
    return base != nullptr && item >= base && item < (base + capacity);
  }

  void releaseOverflowItem(T *item)
  {
    if constexpr (allowOverflow == true)
    {
      if (item != nullptr && isBaseItem(item) == false)
      {
        delete item;
      }
    }
  }

public:

  Pool(const Pool&) = delete;
  Pool& operator=(const Pool&) = delete;
  Pool(Pool&&) = delete;
  Pool& operator=(Pool&&) = delete;

  void initialize(uint32_t count)
  {
    capacity = count;
    watermark = 0;
    base = new T[count];
    available.reserve(count);

    if constexpr (storeOutstanding)
    {
      outstanding = new bytell_hash_set<T *>();
      outstanding->reserve(count);
    }
  }

  Pool() = default;

  Pool(uint32_t count)
  {
    initialize(count);
  }

  ~Pool()
  {
    if constexpr (allowOverflow == true)
    {
      for (T *item : available)
      {
        releaseOverflowItem(item);
      }

      if constexpr (storeOutstanding == true)
      {
        for (T *item : *outstanding)
        {
          releaseOverflowItem(item);
        }
      }
    }

    delete[] base;

    if constexpr (storeOutstanding == true)
    {
      delete outstanding;
    }
  }

  T *get(void)
  {
    T *item = NULL;

    if (watermark == capacity)
    {
      if (available.size())
      {
        item = available.back();
        available.pop_back();
      }
    }
    else
    {
      item = &base[watermark];
      watermark++;
    }

    if constexpr (allowOverflow == true)
    {
      if (unlikely(item == NULL))
      {
        item = new T();
      }
    }

    if constexpr (storeOutstanding == true)
    {
      if (item != nullptr)
      {
        outstanding->insert(item);
      }
    }

    return item;
  }

  template <typename Op>
  void forOutstanding(Op&& doOperation)
  {
    if constexpr (storeOutstanding == true)
    {
      for (T *item : *outstanding)
      {
        doOperation(item);
      }
    }
  }

  uint32_t outstandingCount(void)
  {
    if constexpr (storeOutstanding)
    {
      return outstanding->size();
    }
    else
    {
      return 0;
    }
  }

  bool contains(void *item)
  {
    if constexpr (storeOutstanding)
    {
      return outstanding->contains((T *)item);
    }
    else
    {
      return false;
    }
  }

  void relinquish(T *item)
  {
    if (item == nullptr)
    {
      return;
    }

    available.push_back(item);

    if constexpr (storeOutstanding == true)
    {
      outstanding->erase(item);
    }
  }
};

class InvariantMemoryPool {
private:

  uint64_t bufferSize;
  uint64_t count;
  uint8_t *memory;
  uint8_t *cursor;
  uint8_t *terminal;
  Vector<uint8_t *> available;

  static bool mappingFailed(uint8_t *buffer)
  {
    return buffer == nullptr || buffer == MAP_FAILED;
  }

  bool isSeedBuffer(uint8_t *buffer) const
  {
    return buffer != nullptr && memory != nullptr && buffer >= memory && buffer < terminal;
  }

  void detachBuffer(Buffer& buffer)
  {
    buffer.setInvariant(static_cast<uint8_t *>(nullptr), 0, 0);
    buffer.head = 0;
  }

  uint8_t *nextBuffer(void)
  {
    if (available.size())
    {
      uint8_t *hottest = available.back();
      available.pop_back();
      return hottest;
    }
    else if (cursor < terminal)
    {
      uint8_t *location = cursor;
      cursor += bufferSize;
      return location;
    }
    else
    {
      return (uint8_t *)mmap(NULL, bufferSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    }
  }

public:

  InvariantMemoryPool(const InvariantMemoryPool&) = delete;
  InvariantMemoryPool& operator=(const InvariantMemoryPool&) = delete;
  InvariantMemoryPool(InvariantMemoryPool&&) = delete;
  InvariantMemoryPool& operator=(InvariantMemoryPool&&) = delete;

  void fillBuffer(Buffer& buffer)
  {
    uint8_t *next = nextBuffer();
    if (mappingFailed(next))
    {
      detachBuffer(buffer);
      return;
    }

    buffer.setInvariant(next, bufferSize, 0);
    buffer.head = 0;
  }

  void relinquishBuffer(Buffer& buffer)
  {
    uint8_t *data = buffer.data();
    if (data != nullptr)
    {
      available.push_back(data);
    }
    detachBuffer(buffer);
  }

  InvariantMemoryPool(uint64_t _bufferSize, uint64_t _count)
      : bufferSize(_bufferSize),
        count(_count)
  {
    memory = (uint8_t *)mmap(NULL, bufferSize * count, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (mappingFailed(memory))
    {
      memory = nullptr;
      cursor = nullptr;
      terminal = nullptr;
      return;
    }

    cursor = memory;
    terminal = memory + (bufferSize * count);
  }

  ~InvariantMemoryPool()
  {
    for (uint8_t *buffer : available)
    {
      if (buffer != nullptr && isSeedBuffer(buffer) == false)
      {
        munmap(buffer, bufferSize);
      }
    }

    if (memory != nullptr)
    {
      munmap(memory, bufferSize * count);
    }
  }
};

class FlexibleMemoryPool {
private:

  struct Entry {

    uint8_t *memory;
    uint64_t size;

    Entry(const Entry&) = default;
    Entry() = default;
    Entry(uint8_t *_memory, uint64_t _size)
        : memory(_memory),
          size(_size)
    {}
  };

  uint64_t bufferSizeSeed;
  Vector<Entry> available;

  static bool mappingFailed(uint8_t *buffer)
  {
    return buffer == nullptr || buffer == MAP_FAILED;
  }

  void detachBuffer(Buffer& buffer)
  {
    buffer.setInvariant(static_cast<uint8_t *>(nullptr), 0, 0);
    buffer.head = 0;
  }

  Entry nextBuffer(void)
  {
    if (available.size())
    {
      Entry hottest = available.back();
      available.pop_back();
      return hottest;
    }
    else
    {
      return Entry((uint8_t *)mmap(NULL, bufferSizeSeed, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0), bufferSizeSeed);
    }
  }

public:

  FlexibleMemoryPool(const FlexibleMemoryPool&) = delete;
  FlexibleMemoryPool& operator=(const FlexibleMemoryPool&) = delete;
  FlexibleMemoryPool(FlexibleMemoryPool&&) = delete;
  FlexibleMemoryPool& operator=(FlexibleMemoryPool&&) = delete;

  void fillBuffer(Buffer& buffer)
  {
    Entry next = nextBuffer();
    if (mappingFailed(next.memory))
    {
      detachBuffer(buffer);
      return;
    }

    buffer.setFlexible(next.memory, next.size);
    buffer.head = 0;
  }

  void relinquishBuffer(Buffer& buffer)
  {
    uint8_t *data = buffer.data();
    uint64_t size = buffer.tentativeCapacity();
    if (data != nullptr && size > 0)
    {
      available.emplace_back(data, size);
    }
    detachBuffer(buffer);
  }

  FlexibleMemoryPool(uint64_t _bufferSizeSeed, uint16_t seedCount)
      : bufferSizeSeed(_bufferSizeSeed)
  {
    available.reserve(seedCount);

    for (uint16_t count = 0; count < seedCount; count++)
    {
      uint8_t *memory = (uint8_t *)mmap(NULL, _bufferSizeSeed, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
      if (mappingFailed(memory) == false)
      {
        available.emplace_back(memory, _bufferSizeSeed);
      }
    }
  }

  ~FlexibleMemoryPool()
  {
    for (const Entry& entry : available)
    {
      if (entry.memory != nullptr && entry.size > 0)
      {
        munmap(entry.memory, entry.size);
      }
    }
  }
};
