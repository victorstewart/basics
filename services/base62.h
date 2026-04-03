// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

// each digit of base 62 provides 5.95 bits, verus 8 bits

class Base62 {
private:

  constexpr static inline std::string_view base62_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

  static void base62_append(String& buffer, uint8_t index)
  {
    if (index < 61)
    {
      buffer.append(base62_charset[index]);
    }
    else
    {
      buffer.append(base62_charset[61]);
      buffer.append(base62_charset[index - 61]);
    }
  }

public:

  static String toBase62(uint8_t *input, uint8_t inputLength, uint8_t outputLength = 0)
  {
    String base62String;

    uint64_t groups = (uint64_t(inputLength) / 3) * 4;

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

    // Each 6-bit group expands to one or two output characters.
    base62String.reserve(groups * 2);

    for (size_t i = 0; i < inputLength; i += 3)
    {
      // loads up 3 8-bit numbers
      uint32_t v24 = ((input[i] << 16) | ((i + 1 < inputLength) ? input[i + 1] << 8 : 0) | ((i + 2 < inputLength) ? input[i + 2] : 0));

      // 0x3F == 63
      // it processes 6 bits at a time (because 2^6 = 64, and that's the closest number)

      base62_append(base62String, (v24 >> 18) & 0x3F);
      base62_append(base62String, (v24 >> 12) & 0x3F);

      if (i + 1 < inputLength)
      {
        base62_append(base62String, (v24 >> 6) & 0x3F);
      }
      if (i + 2 < inputLength)
      {
        base62_append(base62String, v24 & 0x3F);
      }
    }

    if (outputLength > 0)
    {
      base62String.resize(outputLength);
    }

    return base62String;
  }
};
