// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
// #include <argon2/argon2.h>
#include <cstring>
#include <type_traits>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#pragma once

namespace Crypto {

template <typename T>
constexpr bool isExtendedIntegralV =
    std::is_integral_v<T> ||
    std::is_same_v<std::remove_cvref_t<T>, __int128_t> ||
    std::is_same_v<std::remove_cvref_t<T>, __uint128_t>;

static void fillWithSecureRandomBytes(uint8_t *buffer, uint32_t nBytes)
{
  RAND_bytes(buffer, nBytes);
}

static String randomString(uint32_t length)
{
  constexpr static char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  constexpr static uint8_t charsetLength = sizeof(charset) - 1;

  String value;
  value.reserve(length);
  value.resize(length);

  if (length == 0)
  {
    return value;
  }

  fillWithSecureRandomBytes(value.data(), length);

  for (uint32_t index = 0; index < length; ++index)
  {
    value.data()[index] = static_cast<uint8_t>(charset[value.data()[index] % charsetLength]);
  }

  return value;
}

static String random6DigitNumberString(void)
{
  String code;
  code.reserve(6);
  code.resize(6);

  fillWithSecureRandomBytes(code.data(), 6);

  for (uint32_t index = 0; index < 6; ++index)
  {
    code.data()[index] = static_cast<uint8_t>('0' + (code.data()[index] % 10));
  }

  return code;
}

template <typename T> requires (isExtendedIntegralV<T>)
static T secureRandomNumber(void)
{
  T number;
  fillWithSecureRandomBytes((uint8_t *)&number, sizeof(T));
  return number;
}

static void fillWithInsecureRandomBytes(uint8_t *buffer, uint32_t nBytes)
{
  while (nBytes > 0)
  {
    uint64_t randomNumber = Random::generateNumberWithNBits<64, uint64_t>();

    uint32_t nWorkingBytes = nBytes > 8 ? 8 : nBytes;

    memcpy(buffer, &randomNumber, nWorkingBytes);

    nBytes -= nWorkingBytes;
    buffer += nWorkingBytes;
  }
}

template <typename T> requires (isExtendedIntegralV<T>)
static T insecureRandomNumber(void)
{
  T number;
  fillWithInsecureRandomBytes((uint8_t *)&number, sizeof(T));
  return number;
}

static String saltAndHash(const uint8_t *password, uint32_t passwordLength, const String& salt)
{
  unsigned int digestLength = EVP_MAX_MD_SIZE;
  uint8_t digest[EVP_MAX_MD_SIZE];

  if (HMAC(EVP_sha256(),
           salt.data(),
           static_cast<int>(salt.size()),
           password,
           passwordLength,
           digest,
           &digestLength) == nullptr)
  {
    return {};
  }

  String saltedHash;
  saltedHash.reserve(digestLength);
  saltedHash.resize(digestLength);
  memcpy(saltedHash.data(), digest, digestLength);
  return saltedHash;
}

static String saltAndHash(const String& password, const String& salt)
{
  return saltAndHash(password.data(), static_cast<uint32_t>(password.size()), salt);
}

// static String saltAndHash(uint8_t *password, uint32_t passwordLength, const String& salt)
// {
//    // calculations on Intel NUC
//    // 16MB  costs 90,020us
//    // 32MB  costs 218,165us
//    // 64MB  costs 377,615us
//    // 128MB costs 756,030us

// // relative calculations on m3.small
// // 16MB  costs 50,156us
// // 32MB  costs 121,554us
// // 64MB  costs 210,394us
// // 128MB costs 421,235us

// // int64_t startUs = Time::now<TimeResolution::us>();

// 	#define HASHLEN 32 // aka 256 bits

// 	String saltedHash(HASHLEN);
//    saltedHash.resize(HASHLEN);

// // https://pthree.org/2016/06/28/lets-talk-password-hashing/
// // https://pthree.org/2016/06/29/further-investigation-into-scrypt-and-argon2-password-hashing/

// uint32_t t_cost = 16;         // number of passes
// uint32_t m_cost = 128 * 1024;  // kilobytes memory usage (we started with using 64)
// uint32_t lanes = 1;           // number of lanes
// uint32_t threads = 1;         // number of threads

// 	argon2_context context = {
//  	(uint8_t *)saltedHash.data(),  /* output array, at least HASHLEN in size */
//    HASHLEN, /* digest length */
//    password, /* password array */
//    passwordLength, /* password length */
//    (uint8_t *)salt.data(),  /* salt array */
//    (uint32_t)salt.size(), /* salt length */
//    NULL, 0, /* optional secret data */
//    NULL, 0, /* optional associated data */
//    t_cost, m_cost, lanes, threads,
//    ARGON2_VERSION_13, /* algorithm version */
//    NULL, NULL, /* custom memory allocation / deallocation functions */
//    /* by default only internal memory is cleared (pwd is not wiped) */
//    ARGON2_DEFAULT_FLAGS
// 	};

// 	argon2id_ctx(&context);

// // int64_t endUs = Time::now<TimeResolution::us>();

// return saltedHash;
// }

}; // namespace Crypto
