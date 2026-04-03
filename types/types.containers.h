// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/bytell_hash_map.hpp>

#ifndef USE_MIMALLOC
#error "basics requires USE_MIMALLOC to be explicitly defined to 0, 1, or 2."
#elif USE_MIMALLOC != 0 && USE_MIMALLOC != 1 && USE_MIMALLOC != 2
#error "basics requires USE_MIMALLOC to be one of 0, 1, or 2."
#else

#if USE_MIMALLOC == 2
#include <mimalloc.h>
#endif

template <typename T> concept VoidPointer = std::is_void_v<std::remove_pointer_t<std::remove_cvref_t<T>>>;

template <typename T> concept Pointer = VoidPointer<T> || std::is_pointer_v<std::remove_cvref_t<T>>;

template <typename T> concept Integral = std::is_integral_v<std::remove_cvref_t<T>> || std::is_enum_v<std::remove_cvref_t<T>>;

template <typename T> concept isHashable = requires (const T& a) {
  { a.hash() } -> std::convertible_to<uint64_t>;
};

template <typename T> concept hasEqualsMethod = requires (const T& a, const T& b) {
  { a.equals(b) } -> std::convertible_to<bool>;
};

template <typename T> concept hasEqualOperator = requires (const T& a, const T& b) {
  { a == b } -> std::convertible_to<bool>;
};

template <typename T> concept isEqualityComparable = hasEqualsMethod<T> || hasEqualOperator<T>;

// struct xxH3low
// {
//    template <typename T> requires (Pointer<T> && !isHashable<T>)
//    size_t operator() (const T& key) const // hash the pointer address
//    {
//       auto address = reinterpret_cast<std::uintptr_t>(key);
//       return XXH3_64bits(&address, sizeof(address));
//    }

// template <typename T> requires (std::is_integral_v<T>)
// size_t operator() (const T& key) const
// {
//    return XXH3_64bits(&key, sizeof(key));
// }

// template <typename T> requires (isHashable<T>)
// size_t operator() (const T& key) const
// {
//    return key.hash();
// }

// 	typedef ska::power_of_two_hash_policy hash_policy; // the default is fibonacci, but this is still a little faster
// };

// uint64_t gxhash64(const void *buf, size_t len, int64_t seed);

template <Hasher::SeedPolicy seedPolicy>
struct noncrypto_hasher_with_policy {
  template <typename T> requires (ByteViewableType<T>)
  size_t operator()(const T& key) const
  {
    const ByteStringView view = basics_byte_string_view(key);
    return (view.data == nullptr) ? 0 : Hasher::hash<seedPolicy>(view.data, view.size);
  }

  template <typename T> requires (Pointer<T> && !isHashable<T>)
  size_t operator()(const T& key) const // hash the pointer address
  {
    alignas(16) std::uintptr_t address = reinterpret_cast<std::uintptr_t>(key);
    return Hasher::hash<seedPolicy>(reinterpret_cast<const uint8_t *>(&address), sizeof(address));
  }

  template <typename T> requires (Integral<T>)
  size_t operator()(const T& key) const
  {
    alignas(16) T alignedKey = key;
    return Hasher::hash<seedPolicy>(reinterpret_cast<const uint8_t *>(&alignedKey), sizeof(alignedKey));
  }

  template <typename T>
  requires (isHashable<T> && !ByteViewableType<T> && !Integral<T> && !Pointer<T>)
  size_t operator()(const T& key) const
  {
    return key.hash();
  }

  typedef ska::power_of_two_hash_policy hash_policy; // the default is fibonacci, but this is still a little faster
};

using noncrypto_hasher = noncrypto_hasher_with_policy<Hasher::SeedPolicy::thread_shared>;

struct keys_are_equal {
  // template <typename T> requires (Pointer<T> && !isEqualityComparable<T>)
  // bool operator() (const T& lhs, const T& rhs) const
  // {
  //    return lhs == rhs;
  // }

  // template <typename T> requires (std::is_integral_v<T>)
  // bool operator() (const T& lhs, const T& rhs) const
  // {
  //    return lhs == rhs;
  // }

  template <typename T> requires (ByteViewableType<T>)
  bool operator()(const T& lhs, const T& rhs) const
  {
    const ByteStringView left = basics_byte_string_view(lhs);
    const ByteStringView right = basics_byte_string_view(rhs);

    if (left.size != right.size)
    {
      return false;
    }

    if (left.data == nullptr || right.data == nullptr)
    {
      return (left.data == right.data) && (left.size == right.size);
    }

    return memcmp(left.data, right.data, left.size) == 0;
  }

  template <typename T>
  requires (hasEqualsMethod<T> && !ByteViewableType<T>)
  bool operator()(const T& lhs, const T& rhs) const
  {
    return lhs.equals(rhs);
  }

  template <typename T>
  requires (!hasEqualsMethod<T> && hasEqualOperator<T> && !ByteViewableType<T>)
  bool operator()(const T& lhs, const T& rhs) const
  {
    return lhs == rhs;
  }
};

template <typename Key, typename Value, Hasher::SeedPolicy seedPolicy>
#if USE_MIMALLOC == 2
using bytell_hash_map_with_policy = ska::bytell_hash_map<Key, Value, noncrypto_hasher_with_policy<seedPolicy>, keys_are_equal, mi_stl_allocator<std::pair<Key, Value>>>;
#else
using bytell_hash_map_with_policy = ska::bytell_hash_map<Key, Value, noncrypto_hasher_with_policy<seedPolicy>, keys_are_equal>;
#endif

template <typename Key, typename Value>
using bytell_hash_map = bytell_hash_map_with_policy<Key, Value, Hasher::SeedPolicy::thread_shared>;

template <typename Value, Hasher::SeedPolicy seedPolicy>
#if USE_MIMALLOC == 2
using bytell_hash_set_with_policy = ska::bytell_hash_set<Value, noncrypto_hasher_with_policy<seedPolicy>, keys_are_equal, mi_stl_allocator<Value>>;
#else
using bytell_hash_set_with_policy = ska::bytell_hash_set<Value, noncrypto_hasher_with_policy<seedPolicy>, keys_are_equal>;
#endif

template <typename Value>
using bytell_hash_set = bytell_hash_set_with_policy<Value, Hasher::SeedPolicy::thread_shared>;

#if USE_MIMALLOC == 2
template <typename Value>
using VectorAllocator = mi_stl_allocator<Value>;
#else
template <typename Value>
using VectorAllocator = std::allocator<Value>;
#endif

template <typename Value>
class Vector : public std::vector<Value, VectorAllocator<Value>> {
public:

  using Base = std::vector<Value, VectorAllocator<Value>>;
  using typename Base::const_iterator;
  using typename Base::iterator;

  iterator erase(iterator position)
  {
    return Base::erase(position);
  }

  iterator erase(const_iterator position)
  {
    return Base::erase(position);
  }

  iterator erase(const_iterator first, const_iterator last)
  {
    return Base::erase(first, last);
  }

  bool contains(const Value& value) const
  {
    return std::find(this->begin(), this->end(), value) != this->end();
  }

  void erase(const Value& value)
  {
    if (auto it = std::find(this->begin(), this->end(), value); it != this->end())
    {
      Base::erase(it);
    }
  }
};

template <typename Key, typename SubContainer, typename SubKey, typename Value>
class bytell_hash_subcontainer {
public:

  bytell_hash_map<Key, SubContainer> map;

  auto& operator[](const Key& key)
  {
    return entriesFor(key);
  }

  auto begin(void)
  {
    return map.begin();
  }

  auto find(const Key& key)
  {
    return map.find(key);
  }

  auto end(void)
  {
    return map.end();
  }

  auto erase(auto it)
  {
    return map.erase(it);
  }

  bool contains(const Key& key)
  {
    return map.contains(key);
  }

  auto& entriesFor(const Key& key)
  {
    return map.atOrConstruct(key);
  }

  bool eraseEntriesFor(const Key& key)
  {
    auto it = map.find(key);

    if (it != map.end())
    {
      map.erase(it);
      return true;
    }
    else
    {
      return false;
    }
  }

  template <typename Lambda>
  void eraseSomeEntriesFor(const Key& key, Lambda&& lambda)
  {
    auto it = map.find(key);

    if (it != map.end())
    {
      auto& subcontainer = it->second;

      for (auto subIt = subcontainer.begin(); subIt != subcontainer.end();)
      {
        switch (lambda(*subIt))
        {
          case 0:
            {
              subIt++;
              break;
            }
          case 1:
            {
              subIt = subcontainer.erase(subIt);
              break;
            }
          case 2:
            {
              goto finish;
            }
        }
      }

    finish:

      if (subcontainer.size() == 0)
      {
        map.erase(it);
      }
    }
  }

  template <typename Lambda>
  void eraseAllEntriesAfter(const Key& key, Lambda&& lambda)
  {
    auto it = map.find(key);

    if (it != map.end())
    {
      for (auto& item : it->second)
      {
        lambda(item);
      }

      map.erase(it);
    }
  }

  template <typename Lambda>
  void forEntries(const Key& key, Lambda&& lambda)
  {
    auto it = map.find(key);

    if (it != map.end())
    {
      for (auto& item : it->second)
      {
        lambda(item);
      }
    }
  }

  bool hasEntriesFor(const Key& key)
  {
    return map.contains(key);
  }

  uint32_t countEntriesFor(const Key& key)
  {
    if (auto it = map.find(key); it != map.end())
    {
      return it->second.size();
    }

    return 0;
  }

  uint32_t size(void) const
  {
    return map.size();
  }

  bool isEmpty(void) const
  {
    return map.size() == 0;
  }

  void clear()
  {
    map.clear();
  }

  virtual bool hasEntryFor(const Key& key, const SubKey& subkey) = 0;
  virtual bool eraseEntry(const Key& key, const SubKey& subkey) = 0;
};

template <typename Key, typename SubKey, typename Value>
class bytell_hash_submap : public bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value> {
public:

  using bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value>::find;
  using bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value>::end;
  using bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value>::erase;
  using bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value>::map;
  using bytell_hash_subcontainer<Key, bytell_hash_map<SubKey, Value>, SubKey, Value>::entriesFor;

  Value& entryFor(const Key& key, const SubKey& subkey)
  {
    return entriesFor(key).atOrConstruct(subkey);
  }

  bool hasEntryFor(const Key& key, const SubKey& subkey)
  {
    auto it = find(key);

    if (it == end())
    {
      return false;
    }

    return it->second.contains(subkey);
  }

  bool eraseEntry(const Key& key, const SubKey& subkey)
  {
    auto it = find(key);

    if (it != end())
    {
      it->second.erase(subkey);
      return true;
    }

    return false;
  }

  void insert_or_assign(const Key& key, const SubKey& subkey, const Value& value)
  {
    entriesFor(key).insert_or_assign(subkey, value);
  }

  void insert_or_assign(const Key& key, const SubKey& subkey, Value&& value)
  {
    entriesFor(key).insert_or_assign(subkey, std::move(value));
  }

  template <typename... Args>
  void insert_or_assign(const Key& key, const SubKey& subkey, Args&&...args)
  {
    entriesFor(key).insert_or_assign(subkey, Value(std::forward<Args>(args)...));
  }

  void insert_or_assign(const Key& key, bytell_hash_map<SubKey, Value>&& submap)
  {
    map.insert_or_assign(key, std::move(submap));
  }
};

template <typename Key, typename Value>
class bytell_hash_subset : public bytell_hash_subcontainer<Key, bytell_hash_set<Value>, Value, Value> {
public:

  using bytell_hash_subcontainer<Key, bytell_hash_set<Value>, Value, Value>::find;
  using bytell_hash_subcontainer<Key, bytell_hash_set<Value>, Value, Value>::end;
  using bytell_hash_subcontainer<Key, bytell_hash_set<Value>, Value, Value>::erase;
  using bytell_hash_subcontainer<Key, bytell_hash_set<Value>, Value, Value>::entriesFor;

  bool hasEntryFor(const Key& key, const Value& value)
  {
    auto it = find(key);

    if (it != end())
    {
      return it->second.contains(value);
    }

    return false;
  }

  bool eraseEntry(const Key& key, const Value& value)
  {
    auto it = find(key);

    if (it != end())
    {
      bool result = it->second.erase(value);

      if (it->second.size() == 0)
      {
        erase(key);
      }

      return result;
    }

    return false;
  }

  template <typename... Args>
  void emplace(const Key& key, Args&&...args)
  {
    entriesFor(key).emplace(std::forward<Args>(args)...);
  }

  void insert(const Key& key, const Value& value)
  {
    entriesFor(key).emplace(value);
  }

  void emplace(const Key& key, Value&& value)
  {
    entriesFor(key).emplace(std::move(value));
  }
};

template <typename Key, typename Value> requires (isEqualityComparable<Value>)
class bytell_hash_subvector : public bytell_hash_subcontainer<Key, Vector<Value>, Value, Value> {
public:

  using bytell_hash_subcontainer<Key, Vector<Value>, Value, Value>::find;
  using bytell_hash_subcontainer<Key, Vector<Value>, Value, Value>::end;
  using bytell_hash_subcontainer<Key, Vector<Value>, Value, Value>::erase;
  using bytell_hash_subcontainer<Key, Vector<Value>, Value, Value>::entriesFor;

  bool hasEntryFor(const Key& key, const Value& value)
  {
    auto it = find(key);

    if (it != end())
    {
      for (auto subit = it->second.begin(); subit != it->second.end(); subit++)
      {
        if (*subit == value)
        {
          return true;
        }
      }
    }

    return false;
  }

  template <typename... Args>
  void emplace(const Key& key, Args&&...args)
  {
    entriesFor(key).emplace_back(std::forward<Args>(args)...);
  }

  void insert(const Key& key, const Value& value)
  {
    entriesFor(key).emplace_back(value);
  }

  void insert(const Key& key, Value&& value)
  {
    entriesFor(key).emplace_back(std::move(value));
  }

  bool eraseEntry(const Key& key, const Value& value)
  {
    auto it = find(key);

    if (it != end())
    {
      for (auto subit = it->second.begin(); subit != it->second.end(); subit++)
      {
        if (*subit == value)
        {
          it->second.erase(subit);
          return true;
        }
      }
    }

    return false;
  }
};

template <class, template <class...> class>
constexpr inline bool is_specialization = false;
template <template <class...> class T, class... Args>
constexpr inline bool is_specialization<T<Args...>, T> = true;

template <class T> concept is_Vector = is_specialization<T, Vector>;

#endif
