// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <bitsery/bitsery.h>
#include <bitsery/adapter/buffer.h>
#include <bitsery/ext/pointer.h>
#include <bitsery/ext/inheritance.h>

#include <bitsery/traits/vector.h>
#include <bitsery/traits/string.h>
#include <bitsery/ext/value_range.h>

#include <static_type_info.h>
#include <types/types.containers.h>

#pragma once

namespace bitsery {

namespace ext {

template <uint32_t N>
struct FixedBinarySequence {

  constexpr FixedBinarySequence() = default;

  template <typename S, typename Fnc>
  void serialize(S& s, const uint8_t *buffer, Fnc&& fnc) const
  {
    s.adapter().template writeBuffer<1>(buffer, N);
  }

  template <typename D, typename Fnc>
  void deserialize(D& d, uint8_t *& buffer, Fnc&& fnc) const
  {
    d.adapter().template readBuffer<1>(buffer, N);
  }
};

class BytellHashMap {
public:

  constexpr explicit BytellHashMap() {}

  template <typename S, typename Key, typename Value, Hasher::SeedPolicy seedPolicy, typename Fnc>
  void serialize(S& s, const bytell_hash_map_with_policy<Key, Value, seedPolicy>& map, Fnc&& fnc) const
  {
    details::writeSize(s.adapter(), map.size());

    if (map.size() > 0)
    {
      for (auto& entry : map)
      {
        fnc(s, const_cast<Key&>(entry.first), const_cast<Value&>(entry.second));
      }

      // for (auto& [key, value] : map)
      // {
      //    fnc(s, key, value);
      // }
    }
  }

  template <typename D, typename Key, typename Value, Hasher::SeedPolicy seedPolicy, typename Fnc>
  void deserialize(D& d, bytell_hash_map_with_policy<Key, Value, seedPolicy>& map, Fnc&& fnc) const
  {
    size_t size = 0;
    details::readSize(d.adapter(), size, UINT32_MAX, std::integral_constant<bool, D::TConfig::CheckDataErrors> {});

    map.clear();

    if (size > 0)
    {
      map.reserve(size);

      for (size_t i = 0; i < size; ++i)
      {
        Key key;
        Value value;
        fnc(d, key, value);
        map.emplace(std::move(key), std::move(value));
      }
    }
  }
};

class BytellHashSet {
public:

  constexpr explicit BytellHashSet() {}

  template <typename S, typename Key, Hasher::SeedPolicy seedPolicy, typename Fnc>
  void serialize(S& s, const bytell_hash_set_with_policy<Key, seedPolicy>& set, Fnc&& fnc) const
  {
    details::writeSize(s.adapter(), set.size());

    for (auto& entry : set)
    {
      fnc(s, const_cast<Key&>(entry));
    }
  }

  template <typename D, typename Key, Hasher::SeedPolicy seedPolicy, typename Fnc>
  void deserialize(D& d, bytell_hash_set_with_policy<Key, seedPolicy>& set, Fnc&& fnc) const
  {
    size_t size = 0;
    details::readSize(d.adapter(), size, UINT32_MAX, std::integral_constant<bool, D::TConfig::CheckDataErrors> {});

    set.clear();
    set.reserve(size);

    for (size_t i = 0; i < size; ++i)
    {
      Key key;
      fnc(d, key);
      set.insert(std::move(key));
    }
  }
};

class BytellHashSubvector {
public:

  constexpr BytellHashSubvector() = default;

  // serialization
  template <typename S, typename Key, typename Value, typename Fnc>
  void serialize(S& s, const bytell_hash_subvector<Key, Value>& container, Fnc&& fnc) const
  {
    // 1) write size of container.map
    details::writeSize(s.adapter(), container.map.size());

    // 2) for each entry in the map
    if (container.map.size() > 0)
    {
      for (auto& entry : container.map)
      {
        // entry.first is Key, entry.second is Vector<Value>
        fnc(s, const_cast<Key&>(entry.first), const_cast<Vector<Value>&>(entry.second));
      }
    }
  }

  // deserialization
  template <typename D, typename Key, typename Value, typename Fnc>
  void deserialize(D& d, bytell_hash_subvector<Key, Value>& container, Fnc&& fnc) const
  {
    // read map size
    size_t size = 0;
    details::readSize(d.adapter(), size, UINT32_MAX, std::integral_constant<bool, D::TConfig::CheckDataErrors> {});

    // clear current data
    container.map.clear();

    if (size > 0)
    {
      container.map.reserve(size);
      // read each pair
      for (auto i = 0u; i < size; ++i)
      {
        Key key;
        Vector<Value> subvector;
        fnc(d, key, subvector);
        container.map.emplace(std::move(key), std::move(subvector));
      }
    }
  }
};

struct StaticRTTI {

  template <typename TBase>
  static size_t get(TBase& obj)
  {
    return (size_t)static_type_info::getTypeIndex<TBase>();
  }

  template <typename TBase>
  constexpr static size_t get()
  {
    return (size_t)static_type_info::getTypeIndex<TBase>();
  }

  template <typename TBase, typename TDerived>
  constexpr static TDerived *cast(TBase *obj)
  {
    static_assert(!std::is_pointer<TDerived>::value, "");
    return dynamic_cast<TDerived *>(obj);
  }

  template <typename TBase>
  constexpr static bool isPolymorphic()
  {
    return std::is_polymorphic<TBase>::value;
  }
};
} // namespace ext

namespace traits {

template <uint32_t N, typename T>
struct ExtensionTraits<ext::FixedBinarySequence<N>, T> {
  using TValue = void;
  constexpr static bool SupportValueOverload = false;
  constexpr static bool SupportObjectOverload = true;
  constexpr static bool SupportLambdaOverload = false;
};

template <typename T>
struct ExtensionTraits<ext::BytellHashMap, T> {
  using TValue = void;
  constexpr static bool SupportValueOverload = false;
  constexpr static bool SupportObjectOverload = false;
  constexpr static bool SupportLambdaOverload = true;
};

template <typename T>
struct ExtensionTraits<ext::BytellHashSet, T> {
  using TValue = void;
  constexpr static bool SupportValueOverload = false;
  constexpr static bool SupportObjectOverload = false;
  constexpr static bool SupportLambdaOverload = true;
};

template <>
struct ContainerTraits<String> {
  using TValue = uint8_t;
  constexpr static bool isResizable = true;
  constexpr static bool isContiguous = true;

  static size_t size(const String& string)
  {
    // it's really requesting the capacity
    // only used for serialization
    return string.tentativeCapacity();
  }

  // used on deserialization
  static void resize(String& string, size_t size)
  {
    string.reserve(size);
    string.resize(size);
  }
};

template <typename T>
struct ExtensionTraits<ext::BytellHashSubvector, T> {
  using TValue = void;
  constexpr static bool SupportValueOverload = false;
  constexpr static bool SupportObjectOverload = false;
  constexpr static bool SupportLambdaOverload = true;
};

template <typename T>
struct ContainerTraits<Vector<T>> {
  using TValue = T;
  constexpr static bool isResizable = true;
  constexpr static bool isContiguous = true;

  static size_t size(const Vector<T>& vector)
  {
    // it's really requesting the capacity
    // only used for serialization
    return vector.size();
  }

  // used on deserialization
  static void resize(Vector<T>& vector, size_t size)
  {
    vector.resize(size);
  }

  static auto begin(::Vector<T>& container)
  {
    return container.begin();
  }

  static auto end(::Vector<T>& container)
  {
    return container.end();
  }

  static auto begin(const ::Vector<T>& container)
  {
    return container.begin();
  }

  static auto end(const ::Vector<T>& container)
  {
    return container.end();
  }
};

template <>
struct BufferAdapterTraits<String> {
  static void increaseBufferSize(String& string, size_t cursor, size_t atLeastN)
  {
    size_t prospectiveNewCapacity = 64 + string.tentativeCapacity() * 2;
    if (atLeastN > prospectiveNewCapacity)
    {
      prospectiveNewCapacity = atLeastN * 1.5;
    }

    string.reserve(prospectiveNewCapacity, cursor);
  }

  using TIterator = uint8_t *;
  using TConstIterator = const uint8_t *;
  using TValue = uint8_t;
};

template <>
struct TextTraits<String> {
  using TValue = uint8_t;

  constexpr static bool addNUL = false;

  static size_t length(const String& string)
  {
    return string.size();
  }
};
} // namespace traits
} // namespace bitsery

struct SafeConfig {
  // defines endianness of data that is read from input adapter and written to output adapter.
  constexpr static bitsery::EndiannessType Endianness = bitsery::EndiannessType::LittleEndian;
  // these flags allow to improve deserialization performance if data is trusted
  // enables/disables checks for buffer end or stream read errors in input adapter
  constexpr static bool CheckAdapterErrors = true;
  // enables/disables checks for other errors that can significantly affect performance
  constexpr static bool CheckDataErrors = true;
};

struct FastConfig {
  // defines endianness of data that is read from input adapter and written to output adapter.
  constexpr static bitsery::EndiannessType Endianness = bitsery::EndiannessType::LittleEndian;
  // these flags allow to improve deserialization performance if data is trusted
  // enables/disables checks for buffer end or stream read errors in input adapter
  constexpr static bool CheckAdapterErrors = false;
  // enables/disables checks for other errors that can significantly affect performance
  constexpr static bool CheckDataErrors = false;
};

using bitsery::ext::InheritanceContext;
using bitsery::ext::PointerLinkingContext;
using bitsery::ext::PolymorphicClassesList;
using bitsery::ext::StaticRTTI;

using PointerOwner = bitsery::ext::PointerOwnerBase<StaticRTTI>;

class BitseryEngine {
private:

  using Reader = bitsery::InputBufferAdapter<String, FastConfig>;
  using Writer = bitsery::OutputBufferAdapter<String, FastConfig>;
  using SafeReader = bitsery::InputBufferAdapter<String, SafeConfig>;

  using Context = std::tuple<bitsery::ext::PointerLinkingContext>;
  using Serializer = bitsery::Serializer<Writer, Context>;
  using Deserializer = bitsery::Deserializer<Reader, Context>;
  using SafeDeserializer = bitsery::Deserializer<SafeReader, Context>;

  static inline String reusableBufferView {MemoryType::view};

public:

  // InheritanceContext
  using PolymorphicContext = std::tuple<PointerLinkingContext, bitsery::ext::PolymorphicContext<StaticRTTI>>;
  using PolymorphicSerializer = bitsery::Serializer<Writer, PolymorphicContext>;
  using PolymorphicDeserializer = bitsery::Deserializer<Reader, PolymorphicContext>;

  template <typename T>
  static uint32_t serialize(String& buffer, T&& object, PolymorphicContext&& context)
  {
    PolymorphicSerializer serializer {context, buffer};
    serializer.object(object);
    serializer.adapter().flush();
    buffer.resize(serializer.adapter().writtenBytesCount());
    return buffer.size();
  }

  template <typename T>
  static bool deserialize(const String& buffer, T&& object, PolymorphicContext&& context)
  {
    if (likely(buffer.size()))
    {
      PolymorphicDeserializer deserializer(context, buffer.data(), buffer.size());
      deserializer.object(object);
      return deserializer.adapter().isCompletedSuccessfully();
    }

    return false;
  }

  template <typename T>
  static uint32_t serialize(String& buffer, T&& object)
  {
    Context context;
    Serializer serializer {context, buffer};
    serializer.object(object);
    serializer.adapter().flush();
    buffer.resize(serializer.adapter().writtenBytesCount());
    return (uint32_t)buffer.size();
  }

  template <typename T>
  static uint32_t serializeAtOffset(String& buffer, uint64_t offset, T&& object)
  {
    if (offset > buffer.tentativeCapacity() && buffer.reserve(offset, buffer.size()) == false)
    {
      return 0;
    }

    Context context;
    Serializer serializer {context, buffer};
    serializer.adapter().currentWritePos(offset);
    serializer.object(object);
    serializer.adapter().flush();

    uint64_t writtenBytes = serializer.adapter().writtenBytesCount();
    buffer.resize(writtenBytes);
    return (writtenBytes >= offset) ? uint32_t(writtenBytes - offset) : uint32_t(0);
  }

  template <typename T>
  static uint32_t serialize(uint8_t *buffer, uint8_t *terminal, T&& object)
  {
    reusableBufferView.setInvariant(buffer, terminal - buffer);
    return serialize(reusableBufferView, std::forward<T>(object));
  }

  template <typename T>
  static bool deserialize(const String& buffer, T&& object)
  {
    if (likely(buffer.size()))
    {
      Context context;
      Deserializer deserializer(context, buffer.data(), buffer.size());
      deserializer.object(object);

      return deserializer.adapter().isCompletedSuccessfully();
    }

    return false;
  }

  template <typename T>
  static bool deserializeSafe(const String& buffer, T&& object)
  {
    if (likely(buffer.size()))
    {
      Context context;
      SafeDeserializer deserializer(context, buffer.data(), buffer.size());
      deserializer.object(object);
      return deserializer.adapter().isCompletedSuccessfully();
    }

    return false;
  }

  template <typename T>
  static bool deserialize(const uint8_t *buffer, const uint8_t *terminal, T&& object)
  {
    reusableBufferView.setInvariant(buffer, terminal - buffer);
    return deserialize(reusableBufferView, std::forward<T>(object));
  }

  template <typename BufferLike, typename T>
  requires (ByteStringViewType<BufferLike>)
  static bool deserialize(BufferLike&& buffer, T&& object)
  {
    const ByteStringView view = basics_byte_string_view(buffer);

    if (view.data != nullptr)
    {
      return deserialize(view.data, view.data + view.size, std::forward<T>(object));
    }

    return false;
  }

  template <typename S, typename T>
  static void generic(S&& serializer, T&& item)
  {
    if constexpr (std::is_integral_v<std::remove_reference_t<T>> || std::is_enum_v<std::remove_reference_t<T>>)
    {
      if constexpr (sizeof(T) == 1)
      {
        serializer.value1b(item);
      }
      else if constexpr (sizeof(T) == 2)
      {
        serializer.value2b(item);
      }
      else if constexpr (sizeof(T) == 4)
      {
        serializer.value4b(item);
      }
      else if constexpr (sizeof(T) == 8)
      {
        serializer.value8b(item);
      }
      else if constexpr (sizeof(T) == 16)
      {
        serializer.value16b(item);
      }
    }
    else if constexpr (is_string_v<T>)
    {
      if constexpr (std::is_pointer_v<std::remove_reference_t<T>>)
      {
        serializer.ext(item, PointerOwner {});
        // serializer.text1b(*item, UINT32_MAX);
      }
      else
      {
        serializer.text1b(item, UINT32_MAX);
      }
    }
    else
    {
      if constexpr (std::is_pointer_v<std::remove_reference_t<T>>)
      {
        serializer.ext(item, PointerOwner {});
      }
      else
      {
        serializer.object(item);
      }
    }
  }
};

// template <typename T>
// uint32_t String::serialize(T&& object)
// {
//    clear();
//    return BitseryEngine::serialize(*this, object);
// }

template <typename T>
void String::deserialize(T&& object)
{
  clear();
  BitseryEngine::deserialize(*this, object);
}

template <typename S, typename Key, typename Value, Hasher::SeedPolicy seedPolicy>
static void serialize(S& serializer, bytell_hash_map_with_policy<Key, Value, seedPolicy>& map)
{
  serializer.ext(map, bitsery::ext::BytellHashMap {}, [](S& serializer, Key& key, Value& entry) {
    BitseryEngine::generic(serializer, key);
    BitseryEngine::generic(serializer, entry);
  });
}

template <typename S, typename Key, Hasher::SeedPolicy seedPolicy>
static void serialize(S& serializer, bytell_hash_set_with_policy<Key, seedPolicy>& set)
{
  serializer.ext(set, bitsery::ext::BytellHashSet {}, [](S& serializer, Key& key) {
    BitseryEngine::generic(serializer, key);
  });
}

template <typename S, typename Key, typename Subkey, typename Value>
static void serialize(S& serializer, bytell_hash_submap<Key, Subkey, Value>& map)
{
  serializer.ext(map.map, bitsery::ext::BytellHashMap {}, [](S& serializer, Key& key, auto& submap) {
    BitseryEngine::generic(serializer, key);
    serializer.object(submap);
  });
}

template <typename S, typename Key, typename Subkey>
static void serialize(S& serializer, bytell_hash_subset<Key, Subkey>& map)
{
  serializer.ext(map.map, bitsery::ext::BytellHashMap {}, [](S& serializer, Key& key, auto& subset) {
    BitseryEngine::generic(serializer, key);
    serializer.object(subset);
  });
}

template <typename S, typename Value>
static void serialize(S& s, Vector<Value>& vec)
{
  if constexpr ((std::is_integral_v<Value> && !std::is_same_v<std::remove_cv_t<Value>, bool>) || std::is_enum_v<Value>)
  {
    if constexpr (sizeof(Value) == 1)
    {
      s.container1b(vec, UINT16_MAX);
    }
    else if constexpr (sizeof(Value) == 2)
    {
      s.container2b(vec, UINT16_MAX);
    }
    else if constexpr (sizeof(Value) == 4)
    {
      s.container4b(vec, UINT16_MAX);
    }
    else if constexpr (sizeof(Value) == 8)
    {
      s.container8b(vec, UINT16_MAX);
    }
    else if constexpr (sizeof(Value) == 16)
    {
      s.container16b(vec, UINT16_MAX);
    }
    else
    {
      s.container(vec, UINT16_MAX, [](S& s1, Value& entry) {
        BitseryEngine::generic(s1, entry);
      });
    }
  }
  else
  {
    s.container(vec, UINT16_MAX, [](S& s1, Value& entry) {
      BitseryEngine::generic(s1, entry);
    });
  }
}

template <typename S, typename Key, typename Value>
static void serialize(S& serializer, bytell_hash_subvector<Key, Value>& map)
{
  serializer.ext(map.map, bitsery::ext::BytellHashMap {}, [](S& serializer, Key& key, auto& subvector) {
    BitseryEngine::generic(serializer, key);
    serializer.object(subvector);
  });
}

template <typename S>
static void serialize(S& serializer, String& string)
{
  serializer.text1b(string, UINT32_MAX);
}

template <typename S>
static void serialize(S& serializer, Buffer& buffer)
{
  serializer.value8b(buffer.head);
  serializer.text1b(static_cast<String&>(buffer), UINT32_MAX);
}
