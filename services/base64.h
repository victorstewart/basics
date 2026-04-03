// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

class Base64 {
private:

  constexpr static char _base64EncodingTable[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  constexpr static short _base64DecodingTable[256] = {
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
      -2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
      -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
      -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2};

  static size_t decodeSize(size_t inputSize)
  {
    return floor((inputSize * 3.0) / 4.0);
  }

  static size_t encodeSize(size_t inputSize)
  {
    return ceil((inputSize * 4.0) / 3.0);
  }

  template <typename Transformer>
  static void prep(const uint8_t *, size_t, size_t outputSize, String& output, Transformer&& transformer)
  {
    output.clear();
    output.reserve(outputSize);
    transformer();
    // output.resize(outputSize);
  }

public:

  static void encode(const uint8_t *input, size_t inputSize, String& output)
  {
    prep(input, inputSize, encodeSize(inputSize), output, [&](void) -> void {
      const uint8_t *workingInput = input;
      size_t inputBytesRemaining = inputSize;

      uint8_t *workingOutput = output.data();

      while (inputBytesRemaining > 2) // keep going until we have less than 24 bits
      {
        *workingOutput++ = _base64EncodingTable[workingInput[0] >> 2];
        *workingOutput++ = _base64EncodingTable[((workingInput[0] & 0x03) << 4) + (workingInput[1] >> 4)];
        *workingOutput++ = _base64EncodingTable[((workingInput[1] & 0x0f) << 2) + (workingInput[2] >> 6)];
        *workingOutput++ = _base64EncodingTable[workingInput[2] & 0x3f];

        // we just handled 3 octets (24 bits) of data
        workingInput += 3;
        inputBytesRemaining -= 3;
      }

      // now deal with the tail end of things
      if (inputBytesRemaining != 0)
      {
        *workingOutput++ = _base64EncodingTable[workingInput[0] >> 2];

        if (inputBytesRemaining > 1)
        {
          *workingOutput++ = _base64EncodingTable[((workingInput[0] & 0x03) << 4) + (workingInput[1] >> 4)];
          *workingOutput++ = _base64EncodingTable[(workingInput[1] & 0x0f) << 2];
        }
        else
        {
          *workingOutput++ = _base64EncodingTable[(workingInput[0] & 0x03) << 4];
        }
      }

      output.resize(workingOutput - output.data());
    });
  }

  static bool encode(String& input, String& output)
  {
    encode(input.data(), input.size(), output);
    return true;
  }

  static void encodePadded(const uint8_t *input, size_t inputSize, String& output)
  {
    encode(input, inputSize, output);

    switch (inputSize % 3)
    {
      case 1:
        {
          output.append("=="_ctv);
          break;
        }
      case 2:
        {
          output.append('=');
          break;
        }
      default:
        {
          break;
        }
    }
  }

  static bool encodePadded(String& input, String& output)
  {
    encodePadded(input.data(), input.size(), output);
    return true;
  }

  static void encodeurl(const uint8_t *input, size_t inputSize, String& output)
  {
    encode(input, inputSize, output);

    uint8_t *pend = output.pend();
    uint8_t *cursor = output.data();

    for (; cursor < pend;)
    {
      switch (*cursor)
      {
        case '+':
          {
            *cursor = '-';
            break;
          }
        case '/':
          {
            *cursor = '_';
            break;
          }
        default:
          break;
      }

      ++cursor;
    }
  }

  static bool decode(const uint8_t *input, size_t inputSize, String& output)
  {
    bool result = true;

    prep(input, inputSize, decodeSize(inputSize), output, [&](void) -> void {
      uint8_t *workingOutput = output.data();
      size_t outputSize = 0;
      uint8_t quartet[4] = {0, 0, 0, 0};
      size_t quartetSize = 0;
      bool quartetHasPadding = false;
      bool finished = false;

      for (size_t inputIndex = 0; inputIndex < inputSize; ++inputIndex)
      {
        uint8_t currentByte = input[inputIndex];

        if (currentByte == ' ' || currentByte == '\t' || currentByte == '\n' || currentByte == '\r')
        {
          continue;
        }

        if (finished)
        {
          result = false;
          return;
        }

        if (currentByte == '=')
        {
          quartet[quartetSize++] = 64;
          quartetHasPadding = true;
        }
        else
        {
          int decodedByte = _base64DecodingTable[currentByte];

          if (decodedByte < 0 || quartetHasPadding)
          {
            result = false;
            return;
          }

          quartet[quartetSize++] = decodedByte;
        }

        if (quartetSize == 4)
        {
          if (quartet[0] == 64 || quartet[1] == 64)
          {
            result = false;
            return;
          }

          workingOutput[outputSize++] = (quartet[0] << 2) | (quartet[1] >> 4);

          if (quartet[2] == 64)
          {
            if (quartet[3] != 64)
            {
              result = false;
              return;
            }

            finished = true;
          }
          else
          {
            workingOutput[outputSize++] = (quartet[1] << 4) | (quartet[2] >> 2);

            if (quartet[3] == 64)
            {
              finished = true;
            }
            else
            {
              workingOutput[outputSize++] = (quartet[2] << 6) | quartet[3];
            }
          }

          quartetSize = 0;
          quartetHasPadding = false;
        }
      }

      if (quartetSize != 0)
      {
        if (quartetHasPadding)
        {
          result = false;
          return;
        }

        if (quartetSize == 1)
        {
          result = false;
          return;
        }

        workingOutput[outputSize++] = (quartet[0] << 2) | (quartet[1] >> 4);

        if (quartetSize == 3)
        {
          workingOutput[outputSize++] = (quartet[1] << 4) | (quartet[2] >> 2);
        }
      }

      output.resize(outputSize);
    });

    return result;
  }

  static bool decode(String& input, String& output)
  {
    return decode(input.data(), input.size(), output);
  }
};
