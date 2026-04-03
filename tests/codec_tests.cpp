// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

static void testBase64Encoding(TestSuite& suite)
{
  String output;

  Base64::encode(reinterpret_cast<const uint8_t *>(""), 0, output);
  EXPECT_STRING_EQ(suite, output, ""_ctv);

  Base64::encode(reinterpret_cast<const uint8_t *>("f"), 1, output);
  EXPECT_STRING_EQ(suite, output, "Zg"_ctv);

  Base64::encode(reinterpret_cast<const uint8_t *>("fo"), 2, output);
  EXPECT_STRING_EQ(suite, output, "Zm8"_ctv);

  Base64::encode(reinterpret_cast<const uint8_t *>("foo"), 3, output);
  EXPECT_STRING_EQ(suite, output, "Zm9v"_ctv);

  Base64::encodePadded(reinterpret_cast<const uint8_t *>("f"), 1, output);
  EXPECT_STRING_EQ(suite, output, "Zg=="_ctv);

  Base64::encodePadded(reinterpret_cast<const uint8_t *>("fo"), 2, output);
  EXPECT_STRING_EQ(suite, output, "Zm8="_ctv);

  Base64::encodePadded(reinterpret_cast<const uint8_t *>("foob"), 4, output);
  EXPECT_STRING_EQ(suite, output, "Zm9vYg=="_ctv);

  uint8_t urlBytes[] = {0xfb, 0xff, 0xfe};
  Base64::encodeurl(urlBytes, sizeof(urlBytes), output);
  EXPECT_STRING_EQ(suite, output, "-__-"_ctv);
}

static void testBase64Decoding(TestSuite& suite)
{
  String output;

  EXPECT_TRUE(suite, Base64::decode(reinterpret_cast<const uint8_t *>(""), 0, output));
  EXPECT_STRING_EQ(suite, output, ""_ctv);

  EXPECT_TRUE(suite, Base64::decode(reinterpret_cast<const uint8_t *>("Zm9v"), 4, output));
  EXPECT_STRING_EQ(suite, output, "foo"_ctv);

  EXPECT_TRUE(suite, Base64::decode(reinterpret_cast<const uint8_t *>("Zm8="), 4, output));
  EXPECT_STRING_EQ(suite, output, "fo"_ctv);

  EXPECT_TRUE(suite, Base64::decode(reinterpret_cast<const uint8_t *>("Z m\n9v\t"), 7, output));
  EXPECT_STRING_EQ(suite, output, "foo"_ctv);

  EXPECT_FALSE(suite, Base64::decode(reinterpret_cast<const uint8_t *>("Zm9v$"), 5, output));
  EXPECT_EQ(suite, output.size(), size_t(0));
}

static void testBase62Encoding(TestSuite& suite)
{
  uint8_t empty[] = {0};
  EXPECT_STRING_EQ(suite, Base62::toBase62(empty, 0), ""_ctv);

  uint8_t oneZero[] = {0};
  EXPECT_STRING_EQ(suite, Base62::toBase62(oneZero, 1), "00"_ctv);

  uint8_t twoZeros[] = {0, 0};
  EXPECT_STRING_EQ(suite, Base62::toBase62(twoZeros, 2), "000"_ctv);

  uint8_t threeZeros[] = {0, 0, 0};
  EXPECT_STRING_EQ(suite, Base62::toBase62(threeZeros, 3), "0000"_ctv);

  uint8_t arbitrary[] = {0, 1, 2};
  EXPECT_STRING_EQ(suite, Base62::toBase62(arbitrary, 3), "0042"_ctv);
  EXPECT_STRING_EQ(suite, Base62::toBase62(arbitrary, 3, 2), "00"_ctv);

  uint8_t expanding[] = {0xff, 0xff, 0xff};
  EXPECT_STRING_EQ(suite, Base62::toBase62(expanding, 3), "Z2Z2Z2Z2"_ctv);
}

int main()
{
  TestSuite suite;

  testBase64Encoding(suite);
  testBase64Decoding(suite);
  testBase62Encoding(suite);

  return suite.finish("codec tests");
}
