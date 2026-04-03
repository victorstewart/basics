// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#ifndef BASICS_TESTS_SOURCE_DIR
#error "BASICS_TESTS_SOURCE_DIR must be defined for corpus-backed tests."
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::string_view kBase62Charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

class DeterministicRng {
private:

  uint64_t state_;

public:

  explicit DeterministicRng(uint64_t seed)
      : state_(seed)
  {}

  uint64_t next()
  {
    uint64_t x = state_;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state_ = x;
    return x;
  }

  uint8_t nextByte()
  {
    return static_cast<uint8_t>(next());
  }

  size_t nextBounded(size_t upperExclusive)
  {
    return (upperExclusive == 0) ? 0 : size_t(next() % upperExclusive);
  }
};

static fs::path rawCorpusRoot()
{
  return fs::path(BASICS_TESTS_SOURCE_DIR) / "corpus" / "raw";
}

static fs::path invalidBase64CorpusRoot()
{
  return fs::path(BASICS_TESTS_SOURCE_DIR) / "corpus" / "codec" / "base64" / "invalid";
}

static std::vector<fs::path> sortedCorpusFiles(const fs::path& directory)
{
  std::vector<fs::path> paths;

  for (const fs::directory_entry& entry : fs::directory_iterator(directory))
  {
    if (entry.is_regular_file())
    {
      paths.push_back(entry.path());
    }
  }

  std::sort(paths.begin(), paths.end());
  return paths;
}

static int hexDigitValue(char c)
{
  if (c >= '0' && c <= '9')
  {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f')
  {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F')
  {
    return 10 + (c - 'A');
  }

  return -1;
}

static std::vector<uint8_t> loadHexBytes(const fs::path& path)
{
  std::ifstream stream(path);
  std::string contents((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

  std::vector<uint8_t> bytes;
  int highNibble = -1;

  for (char c : contents)
  {
    if (std::isspace(static_cast<unsigned char>(c)))
    {
      continue;
    }

    int nibble = hexDigitValue(c);
    if (nibble < 0)
    {
      throw std::runtime_error("invalid hex digit in corpus file: " + path.string());
    }

    if (highNibble < 0)
    {
      highNibble = nibble;
    }
    else
    {
      bytes.push_back(static_cast<uint8_t>((highNibble << 4) | nibble));
      highNibble = -1;
    }
  }

  if (highNibble >= 0)
  {
    throw std::runtime_error("odd hex digit count in corpus file: " + path.string());
  }

  return bytes;
}

static std::string loadTextBytes(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::string contents((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

  if (!contents.empty() && contents.back() == '\n')
  {
    contents.pop_back();
    if (!contents.empty() && contents.back() == '\r')
    {
      contents.pop_back();
    }
  }

  return contents;
}

static std::vector<std::vector<uint8_t>> loadRawSeedCorpus()
{
  std::vector<std::vector<uint8_t>> seeds;

  for (const fs::path& path : sortedCorpusFiles(rawCorpusRoot()))
  {
    seeds.push_back(loadHexBytes(path));
  }

  return seeds;
}

static std::vector<std::string> loadInvalidBase64SeedCorpus()
{
  std::vector<std::string> seeds;

  for (const fs::path& path : sortedCorpusFiles(invalidBase64CorpusRoot()))
  {
    seeds.push_back(loadTextBytes(path));
  }

  return seeds;
}

static const uint8_t *dataOrNull(const std::vector<uint8_t>& bytes)
{
  return bytes.empty() ? nullptr : bytes.data();
}

static uint8_t *mutableDataOrNull(const std::vector<uint8_t>& bytes)
{
  return bytes.empty() ? nullptr : const_cast<uint8_t *>(bytes.data());
}

static bool stringEqualsBytes(const String& string, const std::vector<uint8_t>& bytes)
{
  if (string.size() != bytes.size())
  {
    return false;
  }

  if (bytes.empty())
  {
    return true;
  }

  return memcmp(string.data(), bytes.data(), bytes.size()) == 0;
}

static bool stringStartsWith(const String& value, const String& prefix)
{
  return value.size() >= prefix.size() && memcmp(value.data(), prefix.data(), prefix.size()) == 0;
}

static std::vector<uint8_t> makeRandomBytes(DeterministicRng& rng, size_t length)
{
  std::vector<uint8_t> bytes(length);

  for (uint8_t& byte : bytes)
  {
    byte = rng.nextByte();
  }

  return bytes;
}

static String insertWhitespaceEvery(const String& value, size_t stride)
{
  String spaced;

  for (size_t index = 0; index < value.size(); ++index)
  {
    spaced.append(value[index]);

    if (stride > 0 && ((index + 1) % stride) == 0)
    {
      spaced.append('\n');
      spaced.append('\t');
      spaced.append(' ');
    }
  }

  return spaced;
}

static size_t base62GroupCount(size_t inputLength)
{
  size_t groups = (inputLength / 3) * 4;

  switch (inputLength % 3)
  {
    case 1:
      {
        groups += 2;
        break;
      }
    case 2:
      {
        groups += 3;
        break;
      }
    default:
      {
        break;
      }
  }

  return groups;
}

static bool decodeBase62Group(std::string_view encoded, size_t& index, uint8_t& value)
{
  if (index >= encoded.size())
  {
    return false;
  }

  char c = encoded[index++];
  size_t position = kBase62Charset.find(c);
  if (position == std::string_view::npos)
  {
    return false;
  }

  if (position < 61)
  {
    value = static_cast<uint8_t>(position);
    return true;
  }

  if (index >= encoded.size())
  {
    return false;
  }

  size_t suffix = kBase62Charset.find(encoded[index++]);
  if (suffix == std::string_view::npos || suffix > 2)
  {
    return false;
  }

  value = static_cast<uint8_t>(61 + suffix);
  return true;
}

static bool decodeBase62(std::string_view encoded, size_t originalLength, std::vector<uint8_t>& output)
{
  output.clear();

  std::vector<uint8_t> groups;
  groups.reserve(base62GroupCount(originalLength));

  size_t index = 0;
  while (index < encoded.size())
  {
    uint8_t value = 0;
    if (decodeBase62Group(encoded, index, value) == false)
    {
      return false;
    }

    groups.push_back(value);
  }

  if (groups.size() != base62GroupCount(originalLength))
  {
    return false;
  }

  output.reserve(originalLength);

  for (size_t groupIndex = 0; groupIndex < groups.size(); groupIndex += 4)
  {
    uint32_t v24 = uint32_t(groups[groupIndex]) << 18;
    v24 |= uint32_t(groups[groupIndex + 1]) << 12;

    size_t remainingGroups = groups.size() - groupIndex;
    if (remainingGroups > 2)
    {
      v24 |= uint32_t(groups[groupIndex + 2]) << 6;
    }
    if (remainingGroups > 3)
    {
      v24 |= uint32_t(groups[groupIndex + 3]);
    }

    output.push_back(static_cast<uint8_t>((v24 >> 16) & 0xff));
    if (output.size() < originalLength && remainingGroups > 2)
    {
      output.push_back(static_cast<uint8_t>((v24 >> 8) & 0xff));
    }
    if (output.size() < originalLength && remainingGroups > 3)
    {
      output.push_back(static_cast<uint8_t>(v24 & 0xff));
    }
  }

  return output.size() == originalLength;
}

static bool isBase64UrlAlphabet(const String& value)
{
  for (char c : stringViewOf(value))
  {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_'))
    {
      return false;
    }
  }

  return true;
}

static bool isBase62Alphabet(const String& value)
{
  for (char c : stringViewOf(value))
  {
    if (kBase62Charset.find(c) == std::string_view::npos)
    {
      return false;
    }
  }

  return true;
}

static void testSeedCorpusLoads(TestSuite& suite, const std::vector<std::vector<uint8_t>>& seeds, const std::vector<std::string>& invalidBase64Seeds)
{
  EXPECT_TRUE(suite, fs::exists(rawCorpusRoot()));
  EXPECT_TRUE(suite, seeds.empty() == false);
  EXPECT_TRUE(suite, fs::exists(invalidBase64CorpusRoot()));
  EXPECT_TRUE(suite, invalidBase64Seeds.empty() == false);
}

static void testBase64Properties(TestSuite& suite, const std::vector<std::vector<uint8_t>>& seeds, const std::vector<std::string>& invalidBase64Seeds)
{
  String encoded;
  String padded;
  String decoded;
  String urlEncoded;

  for (const std::vector<uint8_t>& seed : seeds)
  {
    Base64::encode(dataOrNull(seed), seed.size(), encoded);
    EXPECT_TRUE(suite, Base64::decode(encoded.data(), encoded.size(), decoded));
    EXPECT_TRUE(suite, stringEqualsBytes(decoded, seed));

    Base64::encodePadded(dataOrNull(seed), seed.size(), padded);
    EXPECT_TRUE(suite, Base64::decode(padded.data(), padded.size(), decoded));
    EXPECT_TRUE(suite, stringEqualsBytes(decoded, seed));

    Base64::encodeurl(dataOrNull(seed), seed.size(), urlEncoded);
    EXPECT_TRUE(suite, isBase64UrlAlphabet(urlEncoded));

    if (padded.size() > 0)
    {
      String invalidLeading(padded);
      invalidLeading.data()[0] = '$';
      EXPECT_FALSE(suite, Base64::decode(invalidLeading.data(), invalidLeading.size(), decoded));

      String invalidTrailing(padded);
      invalidTrailing.append('$');
      EXPECT_FALSE(suite, Base64::decode(invalidTrailing.data(), invalidTrailing.size(), decoded));

      String invalidMiddle(padded);
      invalidMiddle.data()[invalidMiddle.size() / 2] = '%';
      EXPECT_FALSE(suite, Base64::decode(invalidMiddle.data(), invalidMiddle.size(), decoded));

      for (size_t truncatedSize = 0; truncatedSize < padded.size(); ++truncatedSize)
      {
        String truncated(padded.data(), truncatedSize);
        Base64::decode(truncated.data(), truncated.size(), decoded);
      }
    }
  }

  for (const std::string& invalidSeed : invalidBase64Seeds)
  {
    EXPECT_FALSE(suite, Base64::decode(reinterpret_cast<const uint8_t *>(invalidSeed.data()), invalidSeed.size(), decoded));
    EXPECT_EQ(suite, decoded.size(), size_t(0));
  }

  DeterministicRng rng(0x6a09e667f3bcc909ULL);
  for (size_t iteration = 0; iteration < 256; ++iteration)
  {
    std::vector<uint8_t> bytes = makeRandomBytes(rng, rng.nextBounded(192));

    Base64::encode(dataOrNull(bytes), bytes.size(), encoded);
    EXPECT_TRUE(suite, Base64::decode(encoded.data(), encoded.size(), decoded));
    EXPECT_TRUE(suite, stringEqualsBytes(decoded, bytes));

    std::vector<uint8_t> arbitrary = makeRandomBytes(rng, rng.nextBounded(192));
    Base64::decode(dataOrNull(arbitrary), arbitrary.size(), decoded);
  }

  std::vector<uint8_t> largeBytes = makeRandomBytes(rng, 16 * 1024);
  Base64::encodePadded(dataOrNull(largeBytes), largeBytes.size(), padded);
  String spaced = insertWhitespaceEvery(padded, 61);
  EXPECT_TRUE(suite, Base64::decode(spaced.data(), spaced.size(), decoded));
  EXPECT_TRUE(suite, stringEqualsBytes(decoded, largeBytes));
}

static void testBase62Properties(TestSuite& suite, const std::vector<std::vector<uint8_t>>& seeds)
{
  for (const std::vector<uint8_t>& seed : seeds)
  {
    String encoded = Base62::toBase62(mutableDataOrNull(seed), static_cast<uint8_t>(seed.size()));
    EXPECT_TRUE(suite, isBase62Alphabet(encoded));

    std::vector<uint8_t> decoded;
    EXPECT_TRUE(suite, decodeBase62(stringViewOf(encoded), seed.size(), decoded));
    EXPECT_TRUE(suite, decoded == seed);

    if (encoded.size() > 0)
    {
      uint8_t trimmedSize = static_cast<uint8_t>(encoded.size() / 2);
      String trimmed = Base62::toBase62(mutableDataOrNull(seed), static_cast<uint8_t>(seed.size()), trimmedSize);
      EXPECT_EQ(suite, trimmed.size(), size_t(trimmedSize));
      EXPECT_TRUE(suite, stringStartsWith(encoded, trimmed));
    }
  }

  DeterministicRng rng(0xbb67ae8584caa73bULL);
  for (size_t iteration = 0; iteration < 256; ++iteration)
  {
    std::vector<uint8_t> bytes = makeRandomBytes(rng, rng.nextBounded(192));
    String encoded = Base62::toBase62(mutableDataOrNull(bytes), static_cast<uint8_t>(bytes.size()));

    std::vector<uint8_t> decoded;
    EXPECT_TRUE(suite, decodeBase62(stringViewOf(encoded), bytes.size(), decoded));
    EXPECT_TRUE(suite, decoded == bytes);
  }

  std::vector<uint8_t> maxBytes = makeRandomBytes(rng, std::numeric_limits<uint8_t>::max());
  String encoded = Base62::toBase62(mutableDataOrNull(maxBytes), static_cast<uint8_t>(maxBytes.size()));
  EXPECT_TRUE(suite, isBase62Alphabet(encoded));

  std::vector<uint8_t> decoded;
  EXPECT_TRUE(suite, decodeBase62(stringViewOf(encoded), maxBytes.size(), decoded));
  EXPECT_TRUE(suite, decoded == maxBytes);
}

} // namespace

int main()
{
  TestSuite suite;

  std::vector<std::vector<uint8_t>> seeds = loadRawSeedCorpus();
  std::vector<std::string> invalidBase64Seeds = loadInvalidBase64SeedCorpus();

  testSeedCorpusLoads(suite, seeds, invalidBase64Seeds);
  testBase64Properties(suite, seeds, invalidBase64Seeds);
  testBase62Properties(suite, seeds);

  return suite.finish("fuzz/property tests");
}
