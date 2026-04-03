// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <services/bitsery.h>
#include <services/filesystem.h>

enum class ArgumentNature : uint8_t {

  variable,
  fixed
};

enum class TableItOptions : uint8_t {

  justKeys,
  keysAndValues
};

enum class ValueCollectionOptions : uint8_t {

  byCount,
  byCapacity
};

template <Alignment alignment>
struct BinarySequence {

  uint8_t *head;
  uint8_t *tail;

  BinarySequence(uint8_t *_head, uint8_t *_tail)
      : head(_head),
        tail(_tail)
  {}
};

template <typename T>
struct is_BinarySequence : std::false_type {};

template <Alignment alignment>
struct is_BinarySequence<BinarySequence<alignment>> : std::true_type {};

// template <typename T>
// using is_BinarySequence_v = typename is_BinarySequence<T>::value;

template <typename T>
constexpr static inline bool is_BinarySequence_v = is_BinarySequence<typeof_unqual_t<T>>::value;

template <uint8_t header_size>
struct alignas(16) MessageBase {
private:

  template <typename... Args>
  static void variadicWriteDispatch(StringDescendent auto& wBuffer, Args&&...args)
  {
    if constexpr (sizeof...(Args) == 0)
    {
      return;
    }
    else
    {
      auto dispatch = [&]<typename X>(X&& item) -> void {
        if constexpr (is_string_v<X>)
        {
          appendValue(wBuffer, item);
        }
        else if constexpr (BufferBuilderType<X>)
        {
          appendValue(wBuffer, item);
        }
        else if constexpr (is_BinarySequence_v<X>)
        {
          auto execute = [&]<Alignment alignment>(const BinarySequence<alignment>& sequence) -> void {
            appendAlignedBuffer<alignment>(wBuffer, sequence.head, sequence.tail);
          };

          execute(item);
        }
        else
        {
          append(wBuffer, item);
        }
      };

      (dispatch(std::forward<Args>(args)), ...);
    }
  }

public:

  uint32_t size;
  uint16_t topic;
  uint8_t padding; // at the tail, max is 15 because aligned to 16
  const uint8_t headerSize = header_size;

  uint8_t *terminal(void)
  {
    return (uint8_t *)this + size - padding;
  }

  template <typename T, typename... Args>
  static uint32_t appendHeader(StringDescendent auto& wBuffer, T topic, Args&&...args)
  {
    uint32_t headerOffset = wBuffer.size();

    // size(4) topic(2) padding(1) headerSize(1)
    variadicWriteDispatch(wBuffer, uint32_t(0), uint16_t(topic), uint8_t(0), uint8_t(header_size), std::forward<Args>(args)...);

    // wBuffer.advance(header_size);

    return headerOffset;
  }

  template <typename T, typename... Args>
  static void appendEcho(StringDescendent auto& wBuffer, T topic, Args&&...args)
  {
    finish(wBuffer, appendHeader(wBuffer, topic, std::forward<Args>(args)...));
  }

  template <Alignment alignment>
  static uint8_t *alignedPointer(StringDescendent auto& wBuffer)
  {
    wBuffer.template alignTail<alignment>();

    return wBuffer.pTail();
  }

  static void advance(StringDescendent auto& wBuffer, uint32_t steps)
  {
    wBuffer.advance(steps);
  }

  template <Alignment alignment>
  static void append(StringDescendent auto& wBuffer, const uint8_t *bytes, uint32_t length)
  {
    wBuffer.template alignedAppend<alignment>(bytes, length);
  }

  template <Alignment alignment = Alignment::none, typename T>
  static void append(StringDescendent auto& wBuffer, T&& value)
  {
    wBuffer.template alignedAppend<(alignment == Alignment::none ? (Alignment)sizeof(T) : alignment)>(value);
  }

  template <Alignment alignment>
  static void appendAlignedBuffer(StringDescendent auto& wBuffer, const uint8_t *start, uint8_t *end)
  {
    if (unlikely(end <= start))
    {
      return;
    }

    wBuffer.template alignedAppend<alignment>(start, end - start);
  }

  template <Alignment alignment, typename T> requires (std::is_integral_v<T>)
  static void appendAlignedBuffer(StringDescendent auto& wBuffer, const uint8_t *start, T len)
  {
    wBuffer.template alignedAppend<alignment>(start, len);
  }

  static void appendKey(StringDescendent auto& wBuffer, const uint8_t *key, uint8_t keySize)
  {
    wBuffer.template alignedAppend<Alignment::one>(&keySize, 1);
    wBuffer.template alignedAppend<Alignment::eight>(key, keySize);
  }

  static void appendValue(StringDescendent auto& wBuffer, const uint8_t *value, uint32_t valueSize)
  {
    wBuffer.template alignedAppend<Alignment::four>((uint8_t *)&valueSize, sizeof(uint32_t));
    wBuffer.template alignedAppend<Alignment::eight>(value, valueSize);
  }

  static void appendFile(StringDescendent auto& wBuffer, StringDescendent auto&& filePath)
  {
    uint32_t size = Filesystem::fileSize(filePath);
    wBuffer.template alignedAppend<Alignment::four>((uint8_t *)&size, sizeof(uint32_t));

    wBuffer.template alignTail<Alignment::eight>();
    wBuffer.need(size);
    Filesystem::openReadAtClose(-1, filePath, wBuffer);
  }

  template <typename T>
  static void serializeAndAppendObject(StringDescendent auto& wBuffer, T&& object)
  {
    wBuffer.template alignTail<Alignment::four>();
    if (wBuffer.need(sizeof(uint32_t)) == false)
    {
      return;
    }

    uint64_t valueSizeOffset = wBuffer.size();
    wBuffer.advance(sizeof(uint32_t));
    wBuffer.template alignTail<Alignment::eight>();
    uint64_t payloadOffset = wBuffer.size();
    uint32_t serializedSize = BitseryEngine::serializeAtOffset(wBuffer, payloadOffset, std::forward<T>(object));
    *(uint32_t *)(wBuffer.data() + valueSizeOffset) = serializedSize;
  }

  template <typename T>
  static void appendValue(StringDescendent auto& wBuffer, T&& string)
  {
    if constexpr (std::is_pointer_v<T>)
    {
      appendValue(wBuffer, string->data(), string->size());
    }
    else if constexpr (BufferBuilderType<T>)
    {
      appendValue(wBuffer, string.GetBufferPointer(), string.GetSize());
    }
    else
    {
      appendValue(wBuffer, reinterpret_cast<const uint8_t *>(string.data()), string.size());
    }
  }

  static void finish(StringDescendent auto& wBuffer, uint32_t headerOffset)
  {
    uint8_t *realTail = wBuffer.pTail();

    wBuffer.template alignTail<Alignment::sixteen>();

    MessageBase *message = (MessageBase *)(wBuffer.data() + headerOffset);
    message->padding = wBuffer.pTail() - realTail;

    message->size = (wBuffer.size() - headerOffset);
  }

  template <typename T, typename... Args>
  static void construct(StringDescendent auto& wBuffer, T topic, Args&&...args)
  {
    uint32_t headerOffset = appendHeader(wBuffer, topic);

    variadicWriteDispatch(wBuffer, std::forward<Args>(args)...);

    finish(wBuffer, headerOffset);
  }

  template <typename T, typename X, typename... Args>
  static void constructSerialized(StringDescendent auto& wBuffer, X&& object, T topic, Args&&...args)
  {
    uint32_t headerOffset = appendHeader(wBuffer, topic);
    variadicWriteDispatch(wBuffer, std::forward<Args>(args)...); // this writes the header
    serializeAndAppendObject(wBuffer, object);
    finish(wBuffer, headerOffset);
  }

  template <Alignment alignment, uint32_t fixedLength>
  static uint8_t *extractFixedArgPointer(uint8_t *& workingBuffer)
  {
    align<alignment>(workingBuffer);
    uint8_t *buffer = workingBuffer;
    workingBuffer += fixedLength;
    return buffer;
  }

  // reader
  template <ArgumentNature nature, typename SizeType = void, typename ArgumentType>
  static auto extractArg(uint8_t *& workingBuffer, ArgumentType&& value)
  {
    if constexpr (nature == ArgumentNature::fixed)
    {
      align<(Alignment)alignof(ArgumentType)>(workingBuffer);

      value = *(std::remove_reference_t<ArgumentType> *)workingBuffer;
      workingBuffer += sizeof(ArgumentType);

      return sizeof(ArgumentType);
    }
    else if constexpr (nature == ArgumentNature::variable)
    {
      align<(Alignment)alignof(SizeType)>(workingBuffer);

      SizeType size = *(SizeType *)workingBuffer;

      workingBuffer += sizeof(SizeType);

      align<Alignment::eight>(workingBuffer);

      // otherwise we observed a bug where "value" is 4 bytes to the left
      // of where it should be
      std::atomic_thread_fence(std::memory_order_release);

      value = workingBuffer;

      workingBuffer += size;

      return size;
    }
  }

  template <Alignment alignment>
  static void extractBytes(uint8_t *& workingBuffer, uint8_t *output, uint32_t nBytes)
  {
    align<alignment>(workingBuffer);
    memcpy(output, workingBuffer, nBytes);
    workingBuffer += nBytes;
  }

  template <typename VariableSizeType = uint32_t>
  static void extractToStringView(uint8_t *& workingBuffer, String& output)
  {
    uint8_t *data;
    VariableSizeType length = extractArg<ArgumentNature::variable, VariableSizeType>(workingBuffer, data);

    output.setInvariant(data, length);
  }

  template <typename VariableSizeType = uint32_t>
  static void extractToString(uint8_t *& workingBuffer, String& output)
  {
    uint8_t *data;
    VariableSizeType length = extractArg<ArgumentNature::variable, VariableSizeType>(workingBuffer, data);

    output.assign(data, length);
  }

  template <ArgumentNature valueNature = ArgumentNature::variable, typename ValueSizeType = uint32_t, typename Handler>
  static void valueHandler(uint8_t *& workingBuffer, uint8_t *terminal, Handler&& handler)
  {
    while (workingBuffer < terminal)
    {
      if constexpr (valueNature == ArgumentNature::fixed)
      {
        ValueSizeType value = *(ValueSizeType *)workingBuffer;
        workingBuffer += sizeof(ValueSizeType);
        handler(value);
      }
      else
      {
        uint8_t *value;
        ValueSizeType valueSize = extractArg<valueNature, ValueSizeType>(workingBuffer, value);

        handler(value, valueSize);
      }

    }
  }

  template <ValueCollectionOptions options>
  static uint32_t valueCollector(uint8_t *workingBuffer, uint8_t *terminal, uint8_t *& end, uint32_t metricLimit)
  {
    uint32_t metric = 0;

    end = workingBuffer;
    uint8_t *workingStart;

    while (end < terminal)
    {
      workingStart = end;

      align<Alignment::four>(end);
      uint32_t valueSize = *(uint32_t *)end;
      end += sizeof(uint32_t);

      align<Alignment::eight>(end);
      end += valueSize;

      if constexpr (options == ValueCollectionOptions::byCount)
      {
        if (++metric == metricLimit)
        {
          break;
        }
      }
      else if constexpr (options == ValueCollectionOptions::byCapacity)
      {
        if ((end - workingBuffer) > metricLimit)
        {
          end = workingStart;
          metric = end - workingBuffer;
          break;
        }
      }

    }

    return metric;
  }

  static uint32_t valueCounter(uint8_t *buffer, uint8_t *terminal)
  {
    uint8_t *end = nullptr;
    return valueCollector<ValueCollectionOptions::byCount>(buffer, terminal, end, UINT32_MAX);
  }

  // only support variable values for now.. faster terminal checking
  // if we ever had fixed key of 1 byte to a fixed value of 1 byte... we'd have no way of differentiating between the tail 2 or 3 bytes being another entry or padding. so don't do that
  template <ArgumentNature KeyNature = ArgumentNature::variable, typename KeySize = uint8_t, typename Handler>
  static void keyValueHandler(uint8_t *& workingBuffer, uint8_t *terminal, Handler&& handler)
  {
    while (workingBuffer < terminal)
    {
      if constexpr (KeyNature == ArgumentNature::fixed)
      {
        KeySize key;
        extractArg<ArgumentNature::fixed>(workingBuffer, key);

        uint8_t *value;
        uint32_t valueSize = extractArg<ArgumentNature::variable, uint32_t>(workingBuffer, value);

        handler(key, value, valueSize);
      }
      else
      {
        uint8_t *key;
        KeySize keySize = (KeySize)extractArg<KeyNature, KeySize>(workingBuffer, key);

        uint8_t *value;
        uint32_t valueSize = extractArg<ArgumentNature::variable, uint32_t>(workingBuffer, value);

        handler(key, keySize, value, valueSize);
      }
    }
  }

  template <TableItOptions options = TableItOptions::keysAndValues, typename FixedValueType = void, typename Handler>
  static void tableHandler(uint8_t *& workingBuffer, uint8_t *terminal, Handler&& handler)
  {
    uint8_t *key;
    uint8_t keySize = extractArg<ArgumentNature::variable, uint8_t>(workingBuffer, key);

    static uint8_t compositeKey[256];

    memcpy(compositeKey, key, keySize);
    memset(compositeKey + keySize, '.', 1);

    do
    {
      uint8_t *subkey;
      uint8_t subkeySize = extractArg<ArgumentNature::variable, uint8_t>(workingBuffer, subkey);

      memcpy(compositeKey + keySize + 1, subkey, subkeySize);

      if constexpr (options == TableItOptions::justKeys)
      {
        handler(compositeKey, keySize + 1 + subkeySize);
      }
      else if constexpr (options == TableItOptions::keysAndValues)
      {
        if constexpr (std::is_same_v<FixedValueType, void>)
        {
          uint8_t *value;
          uint32_t valueSize = extractArg<ArgumentNature::variable, uint32_t>(workingBuffer, value);

          handler(compositeKey, keySize + 1 + subkeySize, value, valueSize);
        }
        else
        {
          FixedValueType value;
          extractArg<ArgumentNature::fixed, FixedValueType>(workingBuffer, value);
          handler(compositeKey, keySize + 1 + subkeySize, value);
        }
      }

    } while (workingBuffer < terminal);
  }
};

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma clang diagnostic ignored "-Wgnu-empty-struct"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
struct alignas(16) Message : MessageBase<8> {
  static constexpr uint32_t headerBytes = 8;
  uint8_t args[];

  bool isEcho(void)
  {
    return (args == terminal());
  }

  uint32_t payloadSize(void)
  {
    return static_cast<uint32_t>(terminal() - args);
  }
};

union Padding {

  struct {
    uint8_t bit0 : 1;
    uint8_t bit1 : 1;
    uint8_t bit2 : 1;
    uint8_t bit3 : 1;
    uint8_t bit4 : 1;
    uint8_t bit5 : 1;
    uint8_t bit6 : 1;
    uint8_t bit7 : 1;
  } bits;

  uint8_t byte;
};

template <uint8_t header_size>
struct alignas(16) NetworkMessageBase : MessageBase<header_size> {

  uint64_t uniqueID; // allows out of order completion, as well as reliability and peristence across connection breaks
};

struct alignas(16) NetworkMessage : NetworkMessageBase<16> {
  static constexpr uint32_t headerBytes = 16;
  uint8_t args[];

  bool isEcho(void)
  {
    return (args == terminal());
  }
};
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
