// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef USE_MIMALLOC
#error "basics requires USE_MIMALLOC to be explicitly defined to 0, 1, or 2."
#elif USE_MIMALLOC != 0 && USE_MIMALLOC != 1 && USE_MIMALLOC != 2
#error "basics requires USE_MIMALLOC to be one of 0, 1, or 2."
#else

// #include <CppBenchSubstrSearch/substr_search.hpp> // https://github.com/ashvardanian/StringZilla
#include <itoa/jeaiii_to_text.h>
#include <cstring>
#include <base/dtoa_milo.h>
#include <tuple>
#include <utility> // std::index_sequence
#include <sys/mman.h>

#if USE_MIMALLOC == 2
#include <mimalloc.h>
#endif

template <typename T>
using typeof_unqual_t = std::remove_cv_t<std::remove_reference_t<T>>;

constexpr bool equals(const char *a, const char *b, uint32_t length)
{
  while (length-- > 0)
  {
    if (a[length] != b[length])
    {
      return false;
    }
  }

  return true;
}

static inline uint8_t decodeHexNibble(uint8_t digit)
{
  if (digit >= '0' && digit <= '9')
  {
    return uint8_t(digit - '0');
  }
  if (digit >= 'a' && digit <= 'f')
  {
    return uint8_t(10 + digit - 'a');
  }
  if (digit >= 'A' && digit <= 'F')
  {
    return uint8_t(10 + digit - 'A');
  }
  return 0;
}

static inline void decodeHexBytes(uint8_t *output, const uint8_t *input, uint64_t nBytes)
{
  for (uint64_t index = 0; index < nBytes; ++index)
  {
    output[index] = uint8_t((decodeHexNibble(input[index * 2]) << 4) | decodeHexNibble(input[index * 2 + 1]));
  }
}

static inline void encodeHexBytes(uint8_t *output, const uint8_t *input, uint64_t nBytes)
{
  constexpr static uint8_t lut[] = "0123456789abcdef";

  for (uint64_t index = 0; index < nBytes; ++index)
  {
    uint8_t value = input[index];
    output[index * 2] = lut[(value >> 4) & 0x0F];
    output[index * 2 + 1] = lut[value & 0x0F];
  }
}

class String;

template <char... Chars>
class CompileTimeStringView {
private:

  template <uint32_t Offset, unsigned long... Indexs>
  constexpr static auto substr_impl(std::index_sequence<Indexs...>) noexcept
  {
    return CompileTimeStringView<string[Indexs + Offset]...> {};
  }

public:

  constexpr static char string[sizeof...(Chars) + 1] = {Chars..., '\0'};
  constexpr static uint32_t length = sizeof...(Chars);

  constexpr char operator[](uint32_t index) const noexcept
  {
    return string[index];
  }

  template <char... OChars>
  constexpr CompileTimeStringView<Chars..., OChars...> operator+(const CompileTimeStringView<OChars...>&) noexcept
  {
    return {};
  }

  // clang won't allow this because at this point the class hasn't finished being defined
  // static constexpr CompileTimeStringView instance = {};

  constexpr CompileTimeStringView() = default;
  operator String() const;

  constexpr static const char *cbegin() noexcept
  {
    return &string[0];
  }
  constexpr static const char *cend() noexcept
  {
    return &string[length];
  }

  template <uint32_t From, uint32_t To>
  constexpr static auto substr(void) noexcept
  {
    if constexpr (From == To)
    {
      return CompileTimeStringView<>();
    }
    else
    {
      return substr_impl<From>(std::make_index_sequence<To - From> {});
    }
  }

  template <uint32_t index = 0>
  constexpr static bool contains(char value) noexcept
  {
    if constexpr (index >= length)
    {
      return false;
    }
    else if (string[index] == value)
    {
      return true;
    }
    else
    {
      return contains<index + 1>(value);
    }
  }

  constexpr static const char *c_str() noexcept
  {
    return string;
  }

  constexpr static const char *data() noexcept
  {
    return string;
  }
  constexpr static uint32_t size() noexcept
  {
    return length;
  }

  constexpr static uint8_t notChars = 0x1;
  constexpr static uint8_t skipDoubles = 0x2;
  constexpr static uint8_t matchWholeString = 0x2;

  template <class String>
  constexpr static uint32_t find(uint32_t index, String findTheseChars, uint8_t options = 0, uint32_t terminalIndex = length) noexcept
  {
    while (index < terminalIndex)
    {
      if (options == matchWholeString)
      {
        if ((index + findTheseChars.length) <= terminalIndex)
        {
          if (equals(string + index, findTheseChars.string, findTheseChars.length))
          {
            return index;
          }
        }
        else
        {
          return terminalIndex;
        }
      }
      else
      {
        char ch = string[index];

        if (options == skipDoubles)
        {
          if (findTheseChars.contains(ch) && ((index + 1 < terminalIndex) ? !findTheseChars.contains(string[index + 1]) : true))
          {
            return index;
          }
        }
        else if ((options == notChars) == !findTheseChars.contains(ch))
        {
          return index;
        }
      }

      ++index;
    }

    return index;
  }

  template <class String>
  constexpr static bool equal(String&& opposing)
  {
    return (opposing.length == length) && equals(opposing.string, string, length);
  }

  constexpr static bool equal(const char *opposing)
  {
    return (strcmp(string, opposing) == 0);
  }
};

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-string-literal-operator-template"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
template <class Char, Char... Chars>
constexpr auto operator""_ctv() // compile time view
{
  return CompileTimeStringView<static_cast<char>(Chars)...> {};
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

template <typename T, template <char... CharsB> class Template>
struct is_ctv : std::false_type {};

template <char... CharsA, template <char... CharsB> class Template>
struct is_ctv<Template<CharsA...>, Template> : std::true_type {};

template <typename T>
constexpr static inline bool is_ctv_v = is_ctv<typeof_unqual_t<T>, CompileTimeStringView>::value;

template <typename T> concept CompileTimeStringViewType = is_ctv_v<T>;

enum class Copy : uint8_t {

  yes,
  no
};

enum class MemoryType : uint8_t {

  view,
  mmap,
  heap
};

static uint64_t roundUpToMultiple(uint64_t size, uint64_t multiple)
{
  if (size == 0 || multiple == 0)
  {
    return 0;
  }

  uint64_t remainder = size % multiple;
  if (remainder == 0)
  {
    return size;
  }

  uint64_t padding = multiple - remainder;
  if (size > std::numeric_limits<uint64_t>::max() - padding)
  {
    return 0;
  }

  return size + padding;
}

static uint64_t roundUpToPageSize(uint64_t size)
{
  return roundUpToMultiple(size, PAGE_SIZE);
}

static uint64_t roundUpTo16(uint64_t size)
{
  return roundUpToMultiple(size, 16);
}

template <typename T> concept StringType = requires (T string) { string.data(); string.size(); };

template <typename T> concept StringPointerType = requires (T string) { string->data(); string->size(); };

struct ByteStringView {

  const uint8_t *data;
  uint64_t size;
};

template <typename T>
struct byte_string_view_traits {

  constexpr static bool enabled = false;
};

template <typename T>
concept ByteStringViewType = byte_string_view_traits<std::remove_cvref_t<T>>::enabled;

template <typename T> requires (ByteStringViewType<T>)
static ByteStringView basics_byte_string_view(T&& string)
{
  return byte_string_view_traits<std::remove_cvref_t<T>>::view(string);
}

template <typename T> requires (StringType<T> && !ByteStringViewType<T>)
static ByteStringView basics_byte_string_view(T&& string)
{
  return ByteStringView {reinterpret_cast<const uint8_t *>(string.data()), static_cast<uint64_t>(string.size())};
}

template <typename T>
concept ByteViewableType = requires (const std::remove_reference_t<T>& string) {
  { basics_byte_string_view(string) } -> std::same_as<ByteStringView>;
};

template <typename T> concept SimdjsonObject = requires (T string) { string.get_raw_json_string(); };

template <typename T, typename U>
struct decay_equiv : std::is_same<typeof_unqual_t<T>, U>::type {};

template <class T, class U>
constexpr static inline bool decay_equiv_v = decay_equiv<T, U>::value;

template <typename T> concept CompileTimeStringViewType_Sloppy = requires (T ctv) { T::matchWholeString; T::skipDoubles; };

template <typename T> concept BufferBuilderType = requires (T builder) { builder.GetBufferPointer(); builder.GetSize(); };

template <typename T>
constexpr static inline bool dependent_false_v = false;

class CharacterSet {
public:

  constexpr static inline auto lowercase = "abcdefghijklmnopqrstuvwxyz"_ctv;
  constexpr static inline auto alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"_ctv;
  constexpr static inline auto numbers = "0123456789"_ctv;
};

// if you do the wrong thing with view types... you're gonna have a bad time
class String {
protected:

  uint8_t *string = nullptr;
  uint64_t length = 0;
  uint64_t capacity = 0;
  MemoryType memory = MemoryType::heap;

  static uint64_t boundedLength(uint64_t requestedLength, uint64_t availableCapacity)
  {
    return (requestedLength > availableCapacity) ? availableCapacity : requestedLength;
  }

  static bool mmapFailed(const void *mapping)
  {
    return (mapping == nullptr) || (mapping == MAP_FAILED);
  }

  static uint64_t recommendedCapacity(uint64_t currentCapacity, uint64_t requiredCapacity)
  {
    if (requiredCapacity <= currentCapacity)
    {
      return currentCapacity;
    }

    uint64_t proposedCapacity = (currentCapacity < 16) ? 16 : currentCapacity;
    uint64_t growth = (proposedCapacity < 256) ? proposedCapacity : (proposedCapacity / 2);
    if (growth < 16)
    {
      growth = 16;
    }

    if (proposedCapacity > (std::numeric_limits<uint64_t>::max() - growth))
    {
      return requiredCapacity;
    }

    proposedCapacity += growth;
    return (proposedCapacity < requiredCapacity) ? requiredCapacity : proposedCapacity;
  }

  void clampLengthToCapacity(void)
  {
    length = boundedLength(length, capacity);
  }

  void copyFrom(const String& original)
  {
    if (this == &original)
    {
      return;
    }

    if (original.string == nullptr)
    {
      reset();
      return;
    }

    uint64_t originalLength = boundedLength(original.length, original.capacity);

    if (original.memory == MemoryType::view)
    {
      if (memory != MemoryType::view)
      {
        deallocateMemory(false);
      }

      memory = MemoryType::view;
      string = original.string;
      capacity = original.capacity;
      length = originalLength;
      return;
    }

    if (memory != MemoryType::view && string != nullptr && capacity >= originalLength)
    {
      if (originalLength > 0 && string != original.string)
      {
        memcpy(string, original.string, originalLength);
      }
      length = originalLength;
      return;
    }

    reset();

    memory = original.memory;

    switch (memory)
    {
      case MemoryType::heap:
        {
          if (allocate_heap(original.capacity) == false)
          {
            return;
          }

          length = originalLength;
          if (length > 0)
          {
            memcpy(string, original.string, length);
          }
          break;
        }
      case MemoryType::mmap:
        {
          if (allocate_mmap(original.capacity) == false)
          {
            return;
          }

          length = originalLength;
          if (length > 0)
          {
            memcpy(string, original.string, length);
          }
          break;
        }
      case MemoryType::view:
        {
          string = original.string;
          capacity = original.capacity;
          length = originalLength;
          break;
        }
      }
  }

  void moveFrom(String&& original)
  {
    reset();

    if (original.string != nullptr)
    {
      memory = original.memory;
      capacity = original.capacity;
      string = original.string;
      length = boundedLength(original.length, original.capacity);

      original.memory = MemoryType::heap;
      original.string = nullptr;
      original.capacity = 0;
      original.length = 0;
    }
  }

  void deallocateMemory(bool scrub)
  {
    if (string)
    {
      if (scrub)
      {
        zeroOut();
      }

      switch (memory)
      {
        case MemoryType::heap:
          {
#if USE_MIMALLOC == 2
            mi_free(string);
#else
            free(string);
#endif

            break;
          }
        case MemoryType::mmap:
          {
            munmap(string, capacity);
            break;
          }
        case MemoryType::view:
          break;
      }
    }
  }

  bool allocate_heap(uint64_t initialCapacity)
  {
    if (initialCapacity == 0)
    {
      string = nullptr;
      capacity = 0;
      return true;
    }

#if USE_MIMALLOC == 2
    uint64_t roundedCapacity = mi_good_size(initialCapacity);
    if (roundedCapacity == 0)
    {
      string = nullptr;
      capacity = 0;
      return false;
    }
    uint8_t *allocation = (uint8_t *)mi_malloc_aligned(roundedCapacity, 16);
#else
    uint64_t roundedCapacity = roundUpTo16(initialCapacity);
    if (roundedCapacity == 0)
    {
      string = nullptr;
      capacity = 0;
      return false;
    }
    uint8_t *allocation = (uint8_t *)malloc(roundedCapacity); // aligned_alloc then free-ed on ARM64 generates a false "freeing non malloced memory" crash by santizer
#endif

    if (allocation == nullptr)
    {
      string = nullptr;
      capacity = 0;
      return false;
    }

    string = allocation;
    capacity = roundedCapacity;
    return true;
  }

public:

  template <typename T> requires (std::is_integral_v<std::remove_reference_t<T>>)
  explicit String(T number)
  {
    assignItoa(number);
  }

  template <typename T> requires (std::is_floating_point_v<std::remove_reference_t<T>>)
  explicit String(T number, uint8_t nDecimalDigits = 2)
  {
    assignDtoa(number, nDecimalDigits);
  }

  template <typename T> requires (std::is_integral_v<T>)
  static String toHex(T number)
  {
    String string;
    string.assignItoh(number);
    return string;
  }

  template <typename T> requires (std::is_integral_v<T>)
  static T numberFromHexString(StringType auto&& hs)
  {
    using Integer = std::remove_reference_t<T>;
    using Unsigned = std::make_unsigned_t<Integer>;

    const uint8_t *data = reinterpret_cast<const uint8_t *>(hs.data());
    uint64_t size = hs.size();

    if (size >= 2 && data[0] == '0' && (data[1] == 'x' || data[1] == 'X'))
    {
      data += 2;
      size -= 2;
    }

    while (size > 0 && data[0] == '0')
    {
      data += 1;
      size -= 1;
    }

    if (size == 0)
    {
      return Integer(0);
    }

    constexpr uint64_t maxHexDigits = sizeof(Unsigned) * 2;
    if (size > maxHexDigits)
    {
      return Integer(0);
    }

    for (uint64_t index = 0; index < size; ++index)
    {
      uint8_t digit = data[index];
      if ((digit >= '0' && digit <= '9') == false && (digit >= 'a' && digit <= 'f') == false && (digit >= 'A' && digit <= 'F') == false)
      {
        return Integer(0);
      }
    }

    uint8_t paddedHex[maxHexDigits];
    memset(paddedHex, '0', maxHexDigits);
    memcpy(paddedHex + (maxHexDigits - size), data, size);

    uint8_t decodedBytes[sizeof(Unsigned)] = {};
    decodeHexBytes(decodedBytes, paddedHex, sizeof(Unsigned));

    Unsigned number = 0;
    for (uint64_t index = 0; index < sizeof(Unsigned); ++index)
    {
      number = Unsigned((number << 8) | Unsigned(decodedBytes[index]));
    }

    return static_cast<Integer>(number);
  }

  // meant to be called on an default initalized String or Buffer
  bool allocate_mmap(uint64_t initialCapacity)
  {
    memory = MemoryType::mmap;
    if (initialCapacity == 0)
    {
      string = nullptr;
      capacity = 0;
      return true;
    }

    uint64_t roundedCapacity = roundUpToPageSize(initialCapacity);
    if (roundedCapacity == 0)
    {
      string = nullptr;
      capacity = 0;
      return false;
    }

    uint8_t *mapping = (uint8_t *)mmap(NULL, roundedCapacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (mmapFailed(mapping))
    {
      string = nullptr;
      capacity = 0;
      return false;
    }

    capacity = roundedCapacity;
    string = mapping;
    return true;
  }

  String() = default;

  virtual ~String()
  {
    // std::atomic_thread_fence(std::memory_order_seq_cst);

    deallocateMemory(false);
  }

  // empty string
  String(MemoryType _memory)
      : memory(_memory)
  {}

  String(uint8_t *buffer, uint64_t _capacity, Copy copy = Copy::no, int64_t _length = -1)
  {
    length = (buffer == nullptr) ? 0 : boundedLength((_length < 0) ? _capacity : uint64_t(_length), _capacity);

    if (copy == Copy::yes)
    {
      memory = MemoryType::heap;
      if (allocate_heap(_capacity) == false)
      {
        length = 0;
        return;
      }

      if (length > 0)
      {
        memcpy(string, buffer, length);
      }
    }
    else
    {
      memory = MemoryType::view;
      string = buffer;
      capacity = _capacity;
    }
  }

  // obviously don't use this with a view
  String(uint64_t initialCapacity, MemoryType _memory)
      : memory(_memory)
  {
    if (memory == MemoryType::heap)
    {
      allocate_heap(initialCapacity);
    }
    else if (memory == MemoryType::mmap)
    {
      // this must be a multiple of PAGE_SIZE
      allocate_mmap(initialCapacity);
    }
  }

  // aka only ctv, but before we've defined it
  template <typename T> requires (CompileTimeStringViewType_Sloppy<T>)
  String(T&& anon)
      : String((uint8_t *)anon.data(), anon.size() + 1, Copy::no, anon.size())
  {}

  template <typename T> requires (StringPointerType<T>)
  String(T anon)
      : String((uint8_t *)anon->data(), anon->size(), Copy::yes)
  {}

  template <typename T> requires (BufferBuilderType<T>)
  String(T&& builder, Copy copy)
      : String((uint8_t *)builder.GetBufferPointer(), builder.GetSize(), copy)
  {}

  String(const std::string_view& sv, Copy copy = Copy::yes)
      : String((uint8_t *)sv.data(), sv.size(), copy)
  {}

  template <typename T> requires (SimdjsonObject<T>)
  String(T&& json_object)
      : String(json_object.get_string())
  {}

  String(const String& opposing)
  {
    copyFrom(opposing);
  }

  String(const char *opposing)
      : String((uint8_t *)opposing, strlen(opposing), Copy::yes)
  {}

  String& operator=(const String& opposing)
  {
    copyFrom(opposing);
    return *this;
  }

  // ctv
  template <typename T> requires (CompileTimeStringViewType_Sloppy<T>)
  String& operator=(T&& anon)
  {
    reset();
    setInvariant((uint8_t *)anon.data(), anon.size() + 1, anon.size());
    return *this;
  }

  String(String&& opposing)
  {
    moveFrom(std::move(opposing));
  }

  template <auto format, typename... Args>
  String(Args&&...args)
  {
    CompileTimeStringFormatter::snprintf<format>(*this, std::forward<Args>(args)...);
  }

  String& operator=(String&& opposing)
  {
    moveFrom(std::move(opposing));
    return *this;
  }

  static String epochMsToDateTime(int64_t timeMs)
  {
    auto duration = std::chrono::milliseconds(timeMs);
    auto time_point = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(duration);
    std::time_t time_t_utc = std::chrono::system_clock::to_time_t(time_point);
    std::tm utc_tm = *std::gmtime(&time_t_utc);

    String dateTime;
    if (dateTime.reserve(64) == false)
    {
      return dateTime;
    }
    dateTime.resize(std::strftime(reinterpret_cast<char *>(dateTime.data()), 64, "%Y-%m-%d %H:%M:%S", &utc_tm) - 1);

    return dateTime;
  }

  uint8_t& operator[](uint64_t index)
  {
    return string[index];
  }
  const uint8_t& operator[](uint64_t index) const
  {
    return string[index];
  }

  uint64_t hash(void) const
  {
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(string, length);
  }

  bool equals(const String& lhs) const
  {
    return (length == lhs.length) && ((string == lhs.string) || (length == 0) || (memcmp(string, lhs.string, length) == 0));
  }

  template <typename T> requires (std::is_floating_point_v<std::remove_reference_t<T>>)
  void assignDtoa(T number, uint8_t nDecimalDigits = 2)
  {

    clear();
    if (reserve(24) == false) // supposedly 17 is the most but whatever
    {
      return;
    }

    int len = 0;
    dtoa_milo(number, (char *)string, len);
    resize(len);

    // this culling method isn't perfect because the number isn't totally accurate
    // because of how the dtoa_milo method rounds but whatever. we could also choose
    // an accurate dtoa over a fast one?
    int32_t index = findChar('.');

    if (index > -1)
    {
      int32_t cullNDigits = (length - index) - nDecimalDigits - 1;

      if (cullNDigits > 0)
      {
        length -= cullNDigits;
      }
    }
  }

  template <typename T> requires (std::is_integral_v<std::remove_reference_t<T>>)
  void assignItoa(T number)
  {
    clear();

    bool reserved = true;
    if constexpr (sizeof(T) == 16)
    {
      reserved = reserve(40); // 39 (340,282,366,920,938,463,463,374,607,431,768,211,456) + 1 (negative)
    }
    else if constexpr (sizeof(T) == 8)
    {
      reserved = reserve(20); // 19 (9,223,372,036,854,775,807) + 1 (negative)
    }
    else if constexpr (sizeof(T) == 4)
    {
      reserved = reserve(11); // 10 (4,294,967,296) + 1 (negative)
    }
    else if constexpr (sizeof(T) == 2)
    {
      reserved = reserve(6); // 5 (65,536) + 1 (negative)
    }
    else if constexpr (sizeof(T) == 1)
    {
      reserved = reserve(4); // 3 (256) + 1 (negative)
    }

    if (reserved == false)
    {
      return;
    }

    uint8_t *tail = (uint8_t *)jeaiii::to_text_from_integer((char *)string, number);

    resize(tail - string);
  }

  // template <typename T> requires(std::is_integral_v<std::remove_reference_t<T>> && (sizeof(T) < 16))
  // void assignItoh(T number)
  // {
  //    clear();

  // auto countNonZeroBytes = [=] (T value) -> T {

  // uint8_t count = 0;

  // for (size_t i = 0; i < sizeof(T); ++i)
  // {
  //    if ((value >> (i * 8)) & 0xFF) ++count;
  // }

  // return count;
  // };

  // uint8_t nonZeroBytes = countNonZeroBytes(number);

  // reserve(nonZeroBytes * 2 + 2);

  // append("0x"_ctv);

  // auto reverseBytes = [=] (T value) -> T {

  // if constexpr (sizeof(T) == 1)
  // {
  //    // 1 byte, no need to reverse
  //    return value;
  // }
  // else if constexpr (sizeof(T) == 2)
  // {
  //    // 2 bytes, swap the two bytes
  //    return (value >> 8) | (value << 8);
  // }
  // else if constexpr (sizeof(T) == 4)
  // {
  //    // 4 bytes, reverse each byte
  //    return ((value >> 24) & 0x000000FF) |
  //           ((value >> 8) & 0x0000FF00) |
  //           ((value << 8) & 0x00FF0000) |
  //           ((value << 24) & 0xFF000000);
  // }
  // else if constexpr (sizeof(T) == 8)
  // {
  //    // 8 bytes, reverse each byte
  //    return ((value >> 56) & 0x00000000000000FF) |
  //           ((value >> 40) & 0x000000000000FF00) |
  //           ((value >> 24) & 0x0000000000FF0000) |
  //           ((value >> 8)  & 0x00000000FF000000) |
  //           ((value << 8)  & 0x000000FF00000000) |
  //           ((value << 24) & 0x0000FF0000000000) |
  //           ((value << 40) & 0x00FF000000000000) |
  //           ((value << 56) & 0xFF00000000000000);
  // }
  // else
  // {
  //    // Unsupported size, though this shouldn't happen due to static_assert
  //    return value;
  // }
  // };

  // T reversedNumber = reverseBytes(number);

  // encodeHexVec(string + 2, ((uint8_t *)&reversedNumber) + (sizeof(T) - nonZeroBytes), nonZeroBytes);

  // resize(nonZeroBytes * 2 + 2);
  // }

  template <typename T> requires (std::is_integral_v<std::remove_reference_t<T>>)
  void assignItoh(T number)
  {
    clear();
    using Integer = std::remove_reference_t<T>;
    using Unsigned = std::make_unsigned_t<Integer>;

    Unsigned value = static_cast<Unsigned>(number);
    uint8_t bytes[sizeof(Unsigned)] = {};

    for (uint64_t index = 0; index < sizeof(Unsigned); ++index)
    {
      uint64_t shift = (sizeof(Unsigned) - 1 - index) * 8;
      bytes[index] = uint8_t((value >> shift) & Unsigned(0xFF));
    }

    uint64_t start = 0;
    for (; start < sizeof(Unsigned); ++start)
    {
      if (bytes[start] != 0)
      {
        break;
      }
    }

    if (start == sizeof(Unsigned))
    {
      if (reserve(3) == false)
      {
        return;
      }
      append("0x0"_ctv);
      return;
    }

    uint64_t nonZeroBytes = sizeof(Unsigned) - start;
    if (reserve(nonZeroBytes * 2 + 2) == false)
    {
      return;
    }
    append("0x"_ctv);
    encodeHexBytes(string + 2, bytes + start, nonZeroBytes);
    resize(nonZeroBytes * 2 + 2);
  }

  template <typename T>
  static T toNumber(char *data, uint64_t nBytes)
  {
    // we could check if the number requested has enough bits to fit the number of digits in this string
    T val = 0;

    for (uint64_t index = 0; index < nBytes; index++)
    {
      val = val * 10 + uint8_t(data[index] - '0');
    }

    return val;
  }

  template <typename T>
  T toNumber(uint64_t index = 0, uint64_t nBytes = 0)
  {
    if (nBytes == 0)
    {
      nBytes = length;
    }

    return toNumber<T>((char *)(string + index), nBytes);
  }

  template <typename T>
  static T toNumber(StringType auto&& string)
  {
    return toNumber<T>((char *)string.data(), string.size());
  }

  bool isAShellOfItself(void)
  {
    return (string == nullptr);
  }

  bool isInvariant(void)
  {
    return (memory == MemoryType::view);
  }

  void eraseAndFold(uint8_t *eraseHead, uint64_t nBytes)
  {
    // we could bounds check to make this safe... but just don't be a moron

    // memset is technically unnecessary, but we might as well for hypothetical security reasons?
    memset(eraseHead, 0, nBytes);

    uint8_t *eraseTail = eraseHead + nBytes;
    uint8_t *terminal = pTail();

    if (eraseTail < terminal)
    {
      memmove(eraseHead, eraseTail, terminal - eraseTail);
    }

    length -= nBytes;
  }

  template <typename Type> requires (sizeof(Type) == 1)
  void setInvariant(Type *buffer, uint64_t fixedCapacity, int64_t _length = -1)
  {
    memory = MemoryType::view;
    string = (uint8_t *)buffer;
    capacity = fixedCapacity;
    length = (buffer == nullptr) ? 0 : boundedLength((_length < 0) ? fixedCapacity : uint64_t(_length), fixedCapacity);
  }

  void setInvariant(const std::string_view& view)
  {
    setInvariant(view.data(), view.size());
  }

  void setInvariant(const char *buffer)
  {
    setInvariant(buffer, strlen(buffer));
  }

  void setFlexible(uint8_t *buffer, uint64_t seedCapacity)
  {
    memory = MemoryType::mmap;
    string = buffer;
    capacity = seedCapacity;
    length = 0;
  }

  void reset(void)
  {
    deallocateMemory(false);

    memory = MemoryType::heap;
    string = nullptr;
    capacity = 0;
    length = 0;
  }

  void secureReset(void)
  {
    deallocateMemory(true);

    memory = MemoryType::heap;
    string = nullptr;
    capacity = 0;
    length = 0;
  }

  void clear(void)
  {
    length = 0;
  }

  void zeroOut(void)
  {
    clampLengthToCapacity();
    if (string != nullptr && length > 0)
    {
      memset(string, 0, length);
    }
    length = 0;
  }

  void appendTabs(uint32_t nTabs)
  {
    if (nTabs == 0)
    {
      return;
    }

    if (need(nTabs) == false)
    {
      return;
    }

    memset(string + length, '\t', nTabs);
    length += nTabs;
  }

  bool compare(uint64_t location, uint64_t compareLength, const char *comparison) const
  {
    // if you have junk bytes in "empty" slots this will fail obviously
    return (location <= length) && (compareLength <= (length - location)) && (memcmp(string + location, comparison, compareLength) == 0);
  }

  void trim(uint64_t nBytes)
  {
    length = (nBytes >= length) ? 0 : (length - nBytes);
  }

  String substr(uint64_t location, uint64_t size, Copy copy = Copy::yes) const
  {
    if (string == nullptr || location >= length)
    {
      return {};
    }

    uint64_t safeSize = boundedLength(size, length - location);
    return String(string + location, safeSize, copy, safeSize);
  }

  uint8_t *data() const
  {
    return string;
  }

  bool addNullTerminator(void)
  {
    if (string != nullptr && length < capacity)
    {
      string[length] = '\0';
      return true;
    }

    // if this resets it's fine it won't allocate anymore
    if (need(1) == false)
    {
      return false;
    }

    string[length] = '\0';
    return true;
  }

  const char *c_str()
  {
    if (string == nullptr || capacity == 0)
    {
      return "";
    }

    if (unlikely(memory == MemoryType::view))
    {
      if (length < capacity && string[length] == '\0')
      {
        return (const char *)string;
      }

      return "";
    }

    if (addNullTerminator() == false)
    {
      return "";
    }

    return (const char *)string;
  }

  template <typename T>
  T as(void) const
  {
    static_assert(std::is_trivially_copyable_v<T>, "String::as<T>() requires T to be trivially copyable.");

    T t {};
    if (string == nullptr || length < sizeof(T))
    {
      return t;
    }

    memcpy(&t, string, sizeof(T));
    return t;
  }

  bool empty(void) const
  {
    return (length == 0);
  }

  template <typename Type> requires (sizeof(Type) == 1 || std::is_same_v<Type, void>)
  void append(const Type *buffer, uint64_t bufferSize)
  {
    if (bufferSize == 0)
    {
      return;
    }

    if (need(bufferSize) == false)
    {
      return;
    }

    memcpy(string + length, buffer, bufferSize);
    length += bufferSize;
  }

  template <typename T> requires (std::is_integral_v<std::remove_reference_t<T>>)
  void append(T&& scalar)
  {
    append((uint8_t *)&scalar, sizeof(T));

    // need(sizeof(T));
    // *(std::decay_t<T> *)(string + length) = scalar;
    // length += sizeof(T);
  }

  template <typename Enum> requires (std::is_enum_v<std::remove_reference_t<Enum>>)
  void append(Enum&& value)
  {
    append((std::underlying_type_t<std::remove_reference_t<Enum>>)value);
  }

  void append(const String& buffer)
  {
    append(buffer.string, buffer.length);
  }

  // , typename std::enable_if_t<std::is_integral_v<T>>* = nullptr
  template <Alignment alignment, typename T>
  void alignedAppend(T&& scalar)
  {
    int8_t diffSigned = alignedNeed<alignment>(sizeof(T));
    if (unlikely(diffSigned < 0))
    {
      return;
    }

    uint8_t diff = static_cast<uint8_t>(diffSigned);

    memcpy(string + length + diff, &scalar, sizeof(T));
    // *(std::remove_reference_t<T> *)(string + length + diff) = scalar;

    length += diff + sizeof(T);
  }

  template <Alignment alignment>
  void alignedAppend(const uint8_t *buffer, uint64_t bufferSize)
  {
    int8_t diffSigned = alignedNeed<alignment>(bufferSize);
    if (unlikely(diffSigned < 0))
    {
      return;
    }

    uint8_t diff = static_cast<uint8_t>(diffSigned);
    memcpy(string + length + diff, buffer, bufferSize);
    length += diff + bufferSize;
  }

  template <Alignment alignment>
  void alignedAppend(const String& buffer)
  {
    alignedAppend<alignment>(buffer.data(), buffer.size());
  }

  template <Alignment alignment>
  void alignTail(void)
  {
    int8_t diffSigned = alignedNeed<alignment>(0);
    if (unlikely(diffSigned < 0))
    {
      return;
    }

    length += static_cast<uint8_t>(diffSigned);
  }

  void alignTail(Alignment alignment)
  {
    int8_t diffSigned = alignedNeed(alignment, 0);
    if (unlikely(diffSigned < 0))
    {
      return;
    }

    length += static_cast<uint8_t>(diffSigned);
  }

  template <auto format, typename... Args>
  void snprintf(Args&&...args)
  {
    CompileTimeStringFormatter::snprintf<format>(*this, std::forward<Args>(args)...);
  }

  template <auto format, typename... Args>
  void snprintf_add(Args&&...args)
  {
    CompileTimeStringFormatter::snprintf_add<format>(*this, std::forward<Args>(args)...);
  }

  template <auto format, typename... Args>
  void snprintf_tab_add(uint32_t nTabs, Args&&...args)
  {
    appendTabs(nTabs);
    CompileTimeStringFormatter::snprintf_add<format>(*this, std::forward<Args>(args)...);
  }

  template <auto charset>
  void fillWithSecureChars(uint64_t nChars)
  {
    if (reserve(nChars) == false)
    {
      return;
    }

    // positions
    Crypto::fillWithSecureRandomBytes(string, nChars);

    for (uint64_t index = 0; index < nChars; index++)
    {
      string[index] = uint8_t(charset[uint32_t(uint8_t(string[index]) % charset.size())]);
    }

    resize(nChars);
  }

  template <auto charset>
  void fillWithInsecureChars(uint64_t nChars)
  {
    if (reserve(nChars) == false)
    {
      return;
    }

    uint64_t randomNumber = Random::generateNumberWithNBits<64, uint64_t>();

    for (uint64_t index = 0; index < nChars; index++)
    {
      if (index % 8)
      {
        randomNumber = Random::generateNumberWithNBits<64, uint64_t>();
      }

      string[index] = uint8_t(charset[uint32_t(((uint8_t *)(&randomNumber))[index % 8] % charset.size())]);
    }

    resize(nChars);
  }

  // ....

  // defined in BitseryEngine
  // template <typename T>
  // uint32_t serialize(T&& object);

  template <typename T>
  void deserialize(T&& object);
  // ...

  template <typename Type> requires (sizeof(Type) == 1)
  void assign(Type *buffer, uint64_t bufferSize)
  {
    clear();
    append(buffer, bufferSize);
  }

  template <typename T> requires (StringType<T>)
  void assign(T&& opposing)
  {
    assign(opposing.data(), opposing.size());
  }

  void assign(const std::string_view& opposing)
  {
    assign(opposing.data(), opposing.size());
  }

  template <typename T> requires (StringPointerType<T>)
  void assign(T&& opposing)
  {
    assign((uint8_t *)opposing->data(), opposing->size());
  }

  void assign(const char *opposing)
  {
    assign((uint8_t *)opposing, strlen(opposing));
  }

  void setTail(uint8_t *tail)
  {
    if (string == nullptr || tail == nullptr)
    {
      length = 0;
      return;
    }

    uintptr_t begin = reinterpret_cast<uintptr_t>(string);
    uintptr_t end = begin + capacity;
    uintptr_t requestedEnd = reinterpret_cast<uintptr_t>(tail);

    if (requestedEnd <= begin)
    {
      length = 0;
    }
    else if (requestedEnd >= end)
    {
      length = capacity;
    }
    else
    {
      length = requestedEnd - begin;
    }
  }

  uint64_t tentativeCapacity(void) const
  {
    return capacity;
  }

  uint64_t remainingCapacity(void) const
  {
    return (length >= capacity) ? 0 : (capacity - length);
  }

  char charAtIndex(uint64_t index) const
  {
    return string[index];
  }

  char lastChar(void) const
  {
    return string[length - 1]; // obviously don't call this on an empty string lol
  }

  int64_t findChar(char c, uint64_t startingIndex = 0, uint64_t terminalIndex = 0)
  {
    if (terminalIndex == 0)
    {
      terminalIndex = length;
    }

    for (; startingIndex < terminalIndex; startingIndex++)
    {
      if (string[startingIndex] == c)
      {
        return startingIndex;
      }
    }

    return -1;
  }

  int64_t rfindChar(char c, int64_t startingIndex = -1, uint64_t terminalIndex = 0) const
  {
    if (length == 0 || terminalIndex >= length)
    {
      return -1;
    }

    if (startingIndex < 0 || uint64_t(startingIndex) >= length)
    {
      startingIndex = int64_t(length) - 1;
    }

    for (; startingIndex >= 0 && uint64_t(startingIndex) >= terminalIndex; startingIndex--)
    {
      if (string[startingIndex] == c)
      {
        return startingIndex;
      }
    }

    return -1;
  }

  // int64_t findSIMD(uint64_t location, const char *pattern, uint64_t patternLength) const
  // {
  //    static av::span_t needle;
  //    needle.data = (uint8_t *)pattern;
  //    needle.len = patternLength;

  // static av::span_t haystack;
  // haystack.data = string + location;
  // haystack.len = length - location;

  // size_t offset = av::not_found_k;

  // #ifdef __AVX2__
  //    offset = av::speculative_avx2_t{}.next_offset(haystack, needle);
  // #elif __ARM_NEON
  //    offset = av::speculative_neon_t{}.next_offset(haystack, needle);
  // #endif

  // if (likely(offset != av::not_found_k)) return (int32_t)(offset + location);
  // else                                   return -1;
  // }

  bool containsChar(char c)
  {
    return (findChar(c) != -1);
  }

  // bitsery will ask us to resize the buffer, without having updated the length, in that case we need to copy the whole telling us
  virtual bool reserve(uint64_t newCapacity, uint64_t lengthToCopy = 0)
  {
    if (newCapacity > capacity)
    {
      switch (memory)
      {
        case MemoryType::heap:
          {
            if (capacity == 0)
            {
              if (allocate_heap(newCapacity) == false)
              {
                return false;
              }
            }
            else
            {
#if USE_MIMALLOC == 2
              uint64_t roundedCapacity = mi_good_size(newCapacity);
              if (roundedCapacity == 0)
              {
                return false;
              }
              uint8_t *reallocated = (uint8_t *)mi_realloc_aligned((void *)string, size_t(roundedCapacity), 16);
              if (reallocated == nullptr)
              {
                return false;
              }
              string = reallocated;
              capacity = roundedCapacity;
#else
              if (lengthToCopy == 0)
              {
                lengthToCopy = length;
              }
              lengthToCopy = boundedLength(lengthToCopy, capacity);
              clampLengthToCapacity();

              uint64_t roundedCapacity = roundUpTo16(newCapacity);
              if (roundedCapacity == 0)
              {
                return false;
              }

              uint8_t *newString = (uint8_t *)malloc(roundedCapacity);
              if (newString == nullptr)
              {
                return false;
              }

              if (lengthToCopy > 0)
              {
                memcpy(newString, string, lengthToCopy);
              }
              free(string);
              string = newString;
              capacity = roundedCapacity;
#endif
            }
            break;
          }
        case MemoryType::mmap:
          {
            if (unlikely(capacity == 0))
            {
              allocate_mmap(newCapacity);
              if (newCapacity > 0 && string == nullptr)
              {
                return false;
              }
            }
            else
            {
              uint64_t roundedCapacity = roundUpToPageSize(newCapacity);
              if (roundedCapacity == 0)
              {
                return false;
              }

#if __linux__
              uint8_t *newMapping = (uint8_t *)mremap(string, capacity, roundedCapacity, MREMAP_MAYMOVE);
              if (mmapFailed(newMapping))
              {
                return false;
              }
              string = newMapping;
#elif __APPLE__
              uint8_t *newMemory = (uint8_t *)mmap(NULL, roundedCapacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
              if (mmapFailed(newMemory))
              {
                return false;
              }
              clampLengthToCapacity();
              if (length > 0)
              {
                memcpy(newMemory, string, length);
              }
              munmap(string, capacity);
              string = newMemory;
#endif

              capacity = roundedCapacity;
            }
            break;
          }
        case MemoryType::view:
          {
            return false;
          }
      }
    }

    return true;
  }

  bool growCapacityByExponentialDecay(void)
  {
    if (capacity == std::numeric_limits<uint64_t>::max())
    {
      return false;
    }

    return reserve(recommendedCapacity(capacity, capacity + 1));
  }

  template <typename T> requires (sizeof(T) == 1)
  bool equal(const T *opposing, uint64_t opposingSize) const
  {
    return (length == opposingSize) && ((string == reinterpret_cast<const uint8_t *>(opposing)) || (length == 0) || (memcmp(string, opposing, length) == 0));
  }

  template <typename T> requires (StringType<T>)
  bool equal(T&& opposing) const
  {
    return equal(opposing.data(), opposing.size());
  }

  bool need(uint64_t moreBytes)
  {
    if (moreBytes > (std::numeric_limits<uint64_t>::max() - length))
    {
      return false;
    }

    uint64_t requiredCapacity = length + moreBytes;
    return reserve(recommendedCapacity(capacity, requiredCapacity));
  }

  template <Alignment alignment>
  int8_t alignedNeed(uint64_t size)
  {
    uint8_t *tail = string + length;
    align<alignment>(tail);
    uint8_t diff = tail - (string + length);

    if (likely(need(diff + size)))
    {
      return diff;
    }
    else
    {
      return -1;
    }
  }

  int8_t alignedNeed(Alignment alignment, uint64_t size)
  {
    uint8_t *tail = string + length;
    align(alignment, tail);
    uint8_t diff = tail - (string + length);

    if (likely(need(diff + size)))
    {
      return diff;
    }
    else
    {
      return -1;
    }
  }

  void resize(uint64_t newSize)
  {
    length = boundedLength(newSize, capacity);
  }
  void advance(uint64_t stepForward)
  {
    clampLengthToCapacity();
    length += boundedLength(stepForward, capacity - length);
  }

  uint64_t size(void) const
  {
    return length;
  }
  uint8_t *pend(void) const
  {
    return string + length;
  }

  uint8_t *begin(void) const
  {
    return string;
  }
  uint8_t *end(void) const
  {
    return string + length;
  }

  virtual uint8_t *pHead(void) const
  {
    return string;
  }

  uint8_t *pTail(void) const
  {
    return string + length;
  }

  uint8_t *pTerminal(void)
  {
    return string + capacity;
  }

  class CompileTimeStringFormatter {
  protected:

    struct FormatterSegmentTag {};

    template <typename Integer>
    struct ItoaSegment : FormatterSegmentTag {

      uint8_t buffer[40] = {};
      uint32_t length = 0;

      explicit ItoaSegment(Integer value)
      {
        uint8_t *tail = (uint8_t *)jeaiii::to_text_from_integer((char *)buffer, value);
        length = uint32_t(tail - buffer);
      }

      const uint8_t *data() const
      {
        return buffer;
      }

      uint32_t size() const
      {
        return length;
      }
    };

    template <typename Integer>
    struct ItohSegment : FormatterSegmentTag {

      uint8_t buffer[(sizeof(Integer) * 2) + 3] = {};
      uint32_t length = 0;

      explicit ItohSegment(Integer number)
      {
        using Unsigned = std::make_unsigned_t<Integer>;
        Unsigned value = static_cast<Unsigned>(number);
        uint8_t bytes[sizeof(Unsigned)] = {};

        for (uint64_t index = 0; index < sizeof(Unsigned); ++index)
        {
          uint64_t shift = (sizeof(Unsigned) - 1 - index) * 8;
          bytes[index] = uint8_t((value >> shift) & Unsigned(0xFF));
        }

        uint64_t start = 0;
        while (start < sizeof(Unsigned) && bytes[start] == 0)
        {
          ++start;
        }

        if (start == sizeof(Unsigned))
        {
          memcpy(buffer, "0x0", 3);
          length = 3;
          return;
        }

        uint64_t nonZeroBytes = sizeof(Unsigned) - start;
        memcpy(buffer, "0x", 2);
        encodeHexBytes(buffer + 2, bytes + start, nonZeroBytes);
        length = uint32_t(nonZeroBytes * 2 + 2);
      }

      const uint8_t *data() const
      {
        return buffer;
      }

      uint32_t size() const
      {
        return length;
      }
    };

    template <typename FloatingPoint>
    struct DtoaSegment : FormatterSegmentTag {

      uint8_t buffer[24] = {};
      uint32_t length = 0;

      explicit DtoaSegment(FloatingPoint number, uint8_t nDecimalDigits)
      {
        int len = 0;
        dtoa_milo(number, (char *)buffer, len);
        length = uint32_t(len);

        if (length == 0)
        {
          return;
        }

        uint32_t decimalIndex = length;
        for (uint32_t index = 0; index < length; ++index)
        {
          if (buffer[index] == '.')
          {
            decimalIndex = index;
            break;
          }
        }

        if (decimalIndex < length)
        {
          uint32_t keepLength = decimalIndex + 1 + nDecimalDigits;
          if (keepLength < length)
          {
            length = keepLength;
          }
        }
      }

      const uint8_t *data() const
      {
        return buffer;
      }

      uint32_t size() const
      {
        return length;
      }
    };

    template <typename T>
    constexpr static inline bool is_formatter_segment_v = std::is_base_of_v<FormatterSegmentTag, typeof_unqual_t<T>>;

    template <auto format, uint32_t workingIndex, uint32_t argumentCount, typename Format = decltype(format), typename Arg, typename... Args>
    constexpr static auto generateSegments(Arg&& arg, Args&&...args)
    {
      if constexpr (argumentCount == 0)
      {
        return std::make_tuple(std::forward<Arg>(arg), std::forward<Args>(args)..., Format::template substr<workingIndex, Format::length>());
      }
      else
      {
        constexpr uint32_t nextItoaFormat = Format::find(workingIndex, "{itoa}"_ctv, Format::matchWholeString);
        constexpr uint32_t nextHexFormat = Format::find(workingIndex, "{itoh}"_ctv, Format::matchWholeString);
        constexpr uint32_t nextDtoaFormat = Format::find(workingIndex, "{dtoa:"_ctv, Format::matchWholeString);
        constexpr uint32_t nextFormat = Format::find(workingIndex, "{}"_ctv, Format::matchWholeString);
        constexpr uint32_t nextOpenBrace = Format::find(workingIndex, "{"_ctv, Format::matchWholeString);

        if constexpr (nextItoaFormat >= Format::length && nextHexFormat >= Format::length && nextDtoaFormat >= Format::length && nextFormat >= Format::length)
        {
          if constexpr (nextOpenBrace < Format::length)
          {
            static_assert(nextOpenBrace >= Format::length, "unsupported compile-time format token; supported tokens are {}, {itoa}, {itoh}, and {dtoa:N}");
          }
          else
          {
            static_assert(argumentCount == 0, "too many arguments for compile-time format string");
          }
        }

        if constexpr (nextItoaFormat < nextFormat && nextItoaFormat < nextHexFormat && nextItoaFormat < nextDtoaFormat)
        {
          constexpr uint32_t itoaFormatTermination = nextItoaFormat + 5;

          return generateSegments<format, itoaFormatTermination + 1, argumentCount - 1>(std::forward<Args>(args)..., Format::template substr<workingIndex, nextItoaFormat>(), ItoaSegment<std::remove_cvref_t<Arg>> {std::forward<Arg>(arg)});
        }
        else if constexpr (nextHexFormat < nextFormat && nextHexFormat < nextDtoaFormat)
        {
          constexpr uint32_t hexFormatTermination = nextHexFormat + 5;

          return generateSegments<format, hexFormatTermination + 1, argumentCount - 1>(std::forward<Args>(args)..., Format::template substr<workingIndex, nextHexFormat>(), ItohSegment<std::remove_cvref_t<Arg>> {std::forward<Arg>(arg)});
        }
        else if constexpr (nextDtoaFormat < nextFormat)
        {
          constexpr uint32_t dtoaFormatTermination = Format::find(nextDtoaFormat + 6, "}"_ctv, Format::matchWholeString);
          constexpr auto nDecimalString = Format::template substr<nextDtoaFormat + 6, dtoaFormatTermination>();

          return generateSegments<format, dtoaFormatTermination + 1, argumentCount - 1>(std::forward<Args>(args)..., Format::template substr<workingIndex, nextDtoaFormat>(), DtoaSegment<std::remove_cvref_t<Arg>> {std::forward<Arg>(arg), String::toNumber<uint8_t>(nDecimalString)});
        }
        else
        {
          constexpr uint32_t formatTermination = nextFormat + 1;

          return generateSegments<format, formatTermination + 1, argumentCount - 1>(std::forward<Args>(args)..., Format::template substr<workingIndex, nextFormat>(), std::forward<Arg>(arg));
        }
      }
    }

    template <bool naturallyAlign, typename T>
    static void writeBytes(uint8_t *start, uint8_t *& writeTo, T&& t)
    {
      if constexpr (decay_equiv_v<T, Alignment>)
      {
        align(t, writeTo);
      }
      else if constexpr (is_ctv_v<T> || decay_equiv_v<T, String>)
      {
        if (t.size() > 0)
        {
          if constexpr (naturallyAlign)
          {
            align<Alignment::eight>(writeTo);
          }

          memcpy(writeTo, t.data(), t.size());
          writeTo += t.size();
        }
      }
      else if constexpr (is_formatter_segment_v<T>)
      {
        if (t.size() > 0)
        {
          if constexpr (naturallyAlign)
          {
            align<Alignment::eight>(writeTo);
          }

          memcpy(writeTo, t.data(), t.size());
          writeTo += t.size();
        }
      }
      else if constexpr (sizeof(T) == 16 || std::is_integral_v<std::remove_reference_t<T>> || std::is_floating_point_v<std::remove_reference_t<T>> || std::is_enum_v<std::remove_reference_t<T>>)
      {
        if constexpr (naturallyAlign)
        {
          align<(Alignment)alignof(T)>(writeTo);
        }
        memcpy(writeTo, &t, sizeof(T));
        writeTo += sizeof(T);
      }
      else
      {
        auto lambda = [&]<Alignment alignment>(const void *buffer, const uint32_t bufferSize) {
          if constexpr (naturallyAlign)
          {
            align<alignment>(writeTo);
          }

          if (bufferSize > 0)
          {
            memcpy(writeTo, buffer, bufferSize);
            writeTo += bufferSize;
          }
        };

        snprintf_specialization(lambda, std::forward<T>(t));
      }
    }

    template <bool naturallyAlign, bool overwrite, typename... Args>
    static void snprintf_impl(uint32_t writePosition, uint8_t alignmentNeighbor, uint8_t maxAlignmentPadding, String& workingString, Args&&...args)
    {
      if (workingString.isInvariant() == false)
      {
        // the surpluses here are all 0 because this is run at run time not compile
        uint64_t lengths = 0;

        if constexpr (sizeof...(Args) > 1)
        {
          lengths = (getLength<naturallyAlign>(std::forward<Args>(args)) + ...);
        }
        else if constexpr (sizeof...(Args) == 1)
        {
          lengths = getLength<naturallyAlign>(std::forward<Args>(args)...);
        }

        lengths += maxAlignmentPadding;

        // grow string to accomodate new size if necessary,
        if (workingString.need(lengths) == false)
        {
          return;
        }

        if constexpr (overwrite == false)
        {
          // shift over existing contents
          if (writePosition < workingString.size())
          {
            if (alignmentNeighbor)
            {
              // the length given will be the maximum possible length given worst case alignment. so if we shift by that, we'll have to shift back again.
              // only used in cases where you append the operation type + key

              // 4 bytes size, 1 byte topic, 1 byte key, 2 padding for 8 byte aligned string, string length, padding
              void *movePoint = workingString.data() + writePosition + lengths + 2; // padding
              align((Alignment)alignmentNeighbor, movePoint);
              memmove(movePoint, workingString.data() + writePosition, workingString.size() - writePosition);
            }
            else
            {
              memmove(workingString.data() + writePosition + lengths, workingString.data() + writePosition, workingString.size() - writePosition);
            }
          }
        }
      }

      uint8_t *target = workingString.data() + writePosition;

      (writeBytes<naturallyAlign>(workingString.data() + writePosition, target, std::forward<Args>(args)), ...);

      workingString.setTail(target);
    }

  public:

    template <bool naturallyAlign = false, typename T>
    static uint32_t getLength(T&& t)
    {
      uint32_t length = 0;

      if constexpr (is_ctv_v<T> || decay_equiv_v<T, String>)
      {
        if (t.size() > 0)
        {
          length = t.size();
          if constexpr (naturallyAlign)
          {
            length += 7; // worst case alignment
          }
        }
      }
      else if constexpr (is_formatter_segment_v<T>)
      {
        if (t.size() > 0)
        {
          length = t.size();
          if constexpr (naturallyAlign)
          {
            length += 7;
          }
        }
      }
      else if constexpr (sizeof(T) == 16 || std::is_integral_v<std::remove_reference_t<T>> || std::is_floating_point_v<std::remove_reference_t<T>> || std::is_enum_v<std::remove_reference_t<T>>)
      {
        length = sizeof(T);
        if constexpr (naturallyAlign)
        {
          length += alignof(T) - 1; // worst case alignment
        }
      }
      else
      {
        auto lambda = [&]<Alignment alignment>(const void *buffer, uint32_t bufferSize) {
          length = bufferSize;
          if constexpr (naturallyAlign)
          {
            length += (uint8_t)alignment - 1; // worst case alignment
          }
        };

        snprintf_specialization(lambda, t);
      }

      return length;
    }

    template <auto format, bool overwrite = false, typename... Args>
    static void snprintf_pos(uint32_t writePosition, String& workingString, Args&&...args)
    {
      std::apply([&]<typename... Params>(Params&&...params) {
        // adding this extra level of indirection allowing for the building of higher level abstraction parsers on top
        snprintf_impl<false, overwrite>(writePosition, 0, 0, workingString, std::forward<Params>(params)...);
      },
                 generateSegments<format, 0, sizeof...(Args)>(std::forward<Args>(args)...));
    }

    template <auto format, typename... Args>
    static void snprintf(String& workingString, Args&&...args)
    {
      snprintf_pos<format, true>(0, workingString, std::forward<Args>(args)...);
    }

    template <auto format, typename... Args>
    static void snprintf_add(String& workingString, Args&&...args)
    {
      snprintf_pos<format, false>(workingString.size(), workingString, std::forward<Args>(args)...);
    }
  };
};

using CompileTimeStringFormatter2 = String::CompileTimeStringFormatter;

template <typename T> concept StringDescendent = std::is_base_of_v<String, typeof_unqual_t<T>>;

// so we can use the array new operator
class StringView : public String {
public:

  StringView()
      : String(MemoryType::view)
  {}
};

class Buffer : public String {
public:

  uint64_t head = 0;

  virtual uint8_t *pHead(void) const
  {
    return string + head;
  }

  uint64_t outstandingBytes(void) const
  {
    return length - head;
  }

  bool containsAddress(uint8_t *address)
  {
    return (address >= string) && (address < (string + capacity));
  }

  void shiftHeadToZero(void)
  {
    if (head > 0)
    {
      if (head < length)
      {
        memmove(string, pHead(), outstandingBytes());
      }
      length -= head;
      head = 0;
    }
  }

  // if append would move past capacity, shift the head back to 0
  void shiftAppend(uint8_t *bytes, uint64_t size)
  {
    if ((length + size) > capacity)
    {
      shiftHeadToZero();
    }
    append(bytes, size);
  }

  void reset(void)
  {
    String::reset();
    head = 0;
  }

  void clear(void)
  {
    String::clear();
    head = 0;
  }

  void zeroOut(void)
  {
    String::zeroOut();
    head = 0;
  }

  virtual void consume(uint64_t count, bool zeroIfConsumed)
  {
    const uint64_t outstanding = outstandingBytes();
    if (count >= outstanding)
    {
      if (zeroIfConsumed)
      {
        memset(string, 0, length);
      }

      head = 0;
      length = 0;
      return;
    }

    head += count;
  }

  void softConsume(uint64_t count)
  {
    consume(count, false);
  }

  void hardConsume(uint64_t count)
  {
    consume(count, true);
  }

  void shiftIfTerminal(void)
  {
    if (unlikely((capacity - length) <= (PAGE_SIZE * 64)))
    {
      shiftHeadToZero();
    }
  }

  Buffer() = default;
  Buffer(uint8_t *buffer, uint64_t fixedCapacity)
      : String(buffer, fixedCapacity)
  {}
  Buffer(uint64_t initialCapacity, MemoryType _memoryType = MemoryType::mmap)
      : String(initialCapacity, _memoryType)
  {}
};

template <char... Chars>
CompileTimeStringView<Chars...>::operator String() const
{
  return String((uint8_t *)string, length);
}

template <typename A, typename B>
requires (StringType<A> && StringType<B> && !CompileTimeStringViewType<A> && !CompileTimeStringViewType<B>)
static bool operator==(const A& lhs, const B& rhs)
{
  // lhs.equal(rhs);
  return (lhs.size() == rhs.size()) && ((lhs.data() == rhs.data()) || (lhs.size() == 0) || (memcmp(lhs.data(), rhs.data(), lhs.size()) == 0));
}

template <typename A, typename B>
requires (StringType<A> && StringType<B> && !CompileTimeStringViewType<A> && !CompileTimeStringViewType<B>)
static bool operator!=(const A& lhs, const B& rhs)
{
  return !lhs.equal(rhs);
}

static String operator+(const String& lhs, const String& rhs)
{
  String combo;
  combo.reserve(lhs.size() + rhs.size());
  combo.append(lhs);
  combo.append(rhs);
  return combo;
}

template <typename T> requires (ByteStringViewType<T>)
static bool operator==(const String& lhs, T&& rhs)
{
  const ByteStringView view = basics_byte_string_view(rhs);
  return view.data != nullptr && lhs.equal(view.data, view.size);
}

template <typename T> requires (ByteStringViewType<T>)
static bool operator==(T&& lhs, const String& rhs)
{
  const ByteStringView view = basics_byte_string_view(lhs);
  return view.data != nullptr && rhs.equal(view.data, view.size);
}

template <typename A, typename B>
requires (CompileTimeStringViewType<A> && ByteStringViewType<B>)
constexpr static bool operator==(A&& a, B&& b)
{
  const ByteStringView view = basics_byte_string_view(b);
  return (view.data != nullptr) && (view.size == a.length) && (memcmp(view.data, a.data(), a.length) == 0);
}

template <typename A, typename B>
requires (ByteStringViewType<A> && CompileTimeStringViewType<B>)
constexpr static bool operator==(A&& a, B&& b)
{
  const ByteStringView view = basics_byte_string_view(a);
  return (view.data != nullptr) && (view.size == b.length) && (memcmp(view.data, b.data(), b.length) == 0);
}

template <typename Lambda, typename T>
requires (ByteStringViewType<T>)
static void snprintf_specialization(Lambda&& lambda, T&& t)
{
  const ByteStringView view = basics_byte_string_view(t);
  lambda.template operator()<Alignment::eight>(view.data, view.size);
}

template <typename A, typename B> requires (CompileTimeStringViewType<A> && CompileTimeStringViewType<B>)
constexpr bool operator==(A&& a, B&& b)
{
  return a.equal(b);
}

template <typename A> requires (CompileTimeStringViewType<A>)
constexpr bool operator==(A&& a, const String& b)
{
  return b.equal((const uint8_t *)a.string, a.length);
}

template <typename B> requires (CompileTimeStringViewType<B>)
constexpr bool operator==(const String& a, B&& b)
{
  return a.equal((const uint8_t *)b.string, b.length);
}

template <typename A> requires (CompileTimeStringViewType<A>)
constexpr bool operator==(A&& a, const char *b)
{
  return a.equal(b);
}

template <typename B> requires (CompileTimeStringViewType<B>)
constexpr bool operator==(const char *a, B&& b)
{
  return b.equal(a);
}

template <typename Lambda, typename T>
static void snprintf_specialization(Lambda&& lambda, const T& t)
{
  static_assert(dependent_false_v<T>, "String formatter does not support this argument type.");
}

template <typename Lambda, typename T>
requires (BufferBuilderType<T>)
static void snprintf_specialization(Lambda&& lambda, const T& t)
{
  lambda.template operator()<Alignment::eight>(t.GetBufferPointer(), t.GetSize());
}

template <typename B> requires (CompileTimeStringViewType<B>)
String operator+(const String& a, B&& b)
{
  String c;
  c.reserve(a.size() + b.size());
  c.append(a);
  c.append(b);
  return c;
}

template <typename B> requires (CompileTimeStringViewType<B>)
String& operator+=(String& a, B&& b)
{
  a.append(b);
  return a;
}

template <typename T>
static inline constexpr bool is_string_v = (is_ctv_v<T> || StringDescendent<T> || ByteStringViewType<T>);

// template <typename T>
// static void loopOverTupleForCode(T&& tuple)
// {
//    std::apply([&] (auto&&... params) {

// auto dispatch = [&] <typename X> (X&& item) -> void {

// if constexpr (decay_equiv_v<X, String>)
// {
//    if (item.size() == 6)
//    {
//    }
// }
// };

// (dispatch(params), ...);

// }, tuple);
// }

// template <typename... Args>
// static void loopOverVariadicForCode(Args&&... args)
// {
//    if constexpr (sizeof...(Args) > 0)
//    {
//       auto dispatch = [&] <typename X> (X&& item) -> void {

// if constexpr (decay_equiv_v<X, String>)
// {
//    if (item.size() == 6)
//    {
//    }
// }
// };

// (dispatch(args), ...);
// }
// }

// template <typename T, template <Alignment, typename> class Template>
// struct is_AlignmentPackage : std::false_type {};

// template <Alignment alignmentA, typename TA, template <Alignment alignmentB, typename TB> class Template>
// struct is_AlignmentPackage<Template<alignmentA, TA>, Template> : std::true_type {};

// template <typename T>
// static inline constexpr bool is_AlignmentPackage_v = is_AlignmentPackage<typename std::decay<T>::type, AlignmentPackage>::value;

// template <typename T> requires(std::is_integral_v<std::remove_reference_t<T>>)
// constexpr T reverseByteOrder(T value)
// {
//    T reversed = 0;

// for (size_t i = 0; i < sizeof(T); i++)
// {
//    reversed <<= 8;
//    reversed |= (value & 0xFF);
//    value >>= 8;
// }

// return reversed;
// }

// template <uint32_t capacity>
// class CompileTimeString {
// private:

// uint8_t string[capacity];
// uint32_t length = 0;

// public:

// constexpr uint8_t* data(void) const
// {
//    return string;
// }

// constexpr uint32_t size(void) const
// {
//    return length;
// }

// template <typename T> requires(std::is_integral_v<std::remove_reference_t<T>>)
// constexpr void append(T&& scalar)
// {
//    if (length + sizeof(T) <= capacity)
//    {
//       for (uint8_t i = 0; i < sizeof(T); i++)
//       {
//          string[length + i] = (scalar >> (i * 8)) & 0xFF;
//       }

// length += sizeof(T);
// }
// }

// template <typename... Bytes> requires(sizeof...(Bytes) > 1)
// constexpr void append(Bytes... bytes)
// {
//    constexpr size_t numBytes = sizeof...(Bytes);

// if (length + numBytes <= capacity)
// {
//    ((string[length++] = static_cast<uint8_t>(bytes)), ...);
// }
// }

// constexpr void advance(uint32_t nSteps)
// {
//    length += nSteps;
// }

// // void printHex(void) const
// // {
// //    for (size_t i = 0; i < length; ++i)
// //    {
// //    }
// // }

// constexpr CompileTimeString(void) {}
// };

#endif
