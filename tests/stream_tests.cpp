// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cstdint>
#include <cstring>
#include <limits>
#include <string_view>
#include <vector>

#include "services/filesystem.h"
#include "services/numbers.h"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "services/crypto.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/message.h"
#include "networking/stream.h"

namespace {

enum class StreamTestTopic : uint16_t {
  first = 1,
  second = 2,
};

struct AuxTFOStream : AegisStream {
  String aux;

  String generateAuxTFOData() override
  {
    return aux;
  }
};

static std::string_view outstandingView(const Buffer& buffer)
{
  if (buffer.outstandingBytes() == 0)
  {
    return {};
  }

  return std::string_view(reinterpret_cast<const char *>(buffer.pHead()), buffer.outstandingBytes());
}

static uint32_t roundUpTo16(uint32_t size)
{
  return (size + 15u) & ~15u;
}

static String makeEchoMessage(StreamTestTopic topic)
{
  String message;
  Message::appendEcho(message, topic);
  return message;
}

static String makeEncryptedFrame(uint128_t secret, const String& plaintext)
{
  AegisStream stream;
  stream.secret = secret;
  stream.encrypt(plaintext);

  String frame;
  frame.append(stream.wBuffer.pHead(), stream.wBuffer.outstandingBytes());
  return frame;
}

static void testStreamBufferPreservesHeadAcrossGrowth(TestSuite& suite)
{
  StreamBuffer buffer;
  EXPECT_TRUE(suite, buffer.reserve(8));

  buffer.append("abcdef", 6);
  buffer.consume(2, false);

  EXPECT_TRUE(suite, buffer.reserve(64));
  EXPECT_EQ(suite, buffer.outstandingBytes(), uint64_t(4));
  EXPECT_TRUE(suite, outstandingView(buffer) == std::string_view("cdef"));
}

static void testStreamBufferDoesNotReplayQueuedBytesAfterGrowth(TestSuite& suite)
{
  StreamBuffer buffer;
  EXPECT_TRUE(suite, buffer.reserve(4));

  buffer.append("abcd", 4);
  uint8_t *queuedHead = buffer.pHead();
  buffer.noteSendQueued();
  buffer.append("efghijkl", 8);

  EXPECT_EQ(suite, buffer.outstandingBytes(), uint64_t(12));
  EXPECT_TRUE(suite, std::memcmp(queuedHead, "abcd", 4) == 0);

  buffer.noteSendCompleted();
  buffer.consume(4, true);
  EXPECT_EQ(suite, buffer.outstandingBytes(), uint64_t(8));
  EXPECT_TRUE(suite, outstandingView(buffer) == std::string_view("efghijkl"));

  buffer.consume(8, true);
  EXPECT_EQ(suite, buffer.outstandingBytes(), uint64_t(0));

  buffer.append("zz", 2);
  EXPECT_TRUE(suite, outstandingView(buffer) == std::string_view("zz"));
}

static void testCleartextFramingAndRangeExtraction(TestSuite& suite)
{
  Stream stream;
  String first = makeEchoMessage(StreamTestTopic::first);
  String second = makeEchoMessage(StreamTestTopic::second);
  String combined;
  combined.append(first);
  combined.append(second);
  stream.rBuffer.append(combined);

  bool failed = true;
  std::vector<uint16_t> seenTopics;
  stream.extractMessages<Message>([&](Message *message) -> void {
    seenTopics.push_back(message->topic);
  },
                                  false, 8, 16, UINT32_MAX, failed);

  EXPECT_FALSE(suite, failed);
  EXPECT_EQ(suite, seenTopics.size(), size_t(2));
  EXPECT_EQ(suite, seenTopics[0], uint16_t(StreamTestTopic::first));
  EXPECT_EQ(suite, seenTopics[1], uint16_t(StreamTestTopic::second));

  uint64_t totalLength = 0;
  uint32_t count = 0;
  EXPECT_FALSE(suite, stream.extractMessageRange<Message>(totalLength, count, 8));
  EXPECT_EQ(suite, totalLength, combined.size());
  EXPECT_EQ(suite, count, uint32_t(2));

  Message *head = stream.hasMessage<Message>(16, UINT32_MAX, failed);
  EXPECT_TRUE(suite, head != nullptr);
  EXPECT_FALSE(suite, failed);
  EXPECT_EQ(suite, head->topic, uint16_t(StreamTestTopic::first));

  stream.consumeHeadMessage<Message>();
  Message *next = stream.hasMessage<Message>(16, UINT32_MAX, failed);
  EXPECT_TRUE(suite, next != nullptr);
  EXPECT_FALSE(suite, failed);
  EXPECT_EQ(suite, next->topic, uint16_t(StreamTestTopic::second));
}

static void testPartialAndMalformedHeadersFailClosed(TestSuite& suite)
{
  Stream partial;
  EXPECT_TRUE(suite, partial.rBuffer.reserve(4));
  partial.rBuffer.append(uint32_t(16));

  bool failed = true;
  Message *message = partial.hasMessage<Message>(16, UINT32_MAX, failed);
  EXPECT_TRUE(suite, message == nullptr);
  EXPECT_FALSE(suite, failed);
  EXPECT_TRUE(suite, partial.rBuffer.tentativeCapacity() >= uint64_t(16));

  Stream malformed;
  String malformedBytes = makeEchoMessage(StreamTestTopic::first);
  malformedBytes.data()[7] = uint8_t(malformedBytes.size() + 1);
  malformed.rBuffer.append(malformedBytes);
  message = malformed.hasMessage<Message>(16, UINT32_MAX, failed);
  EXPECT_TRUE(suite, message == nullptr);
  EXPECT_TRUE(suite, failed);
}

static void testExtractMessageRangeReportsOverflow(TestSuite& suite)
{
  Stream stream;
  String message = makeEchoMessage(StreamTestTopic::first);
  stream.rBuffer.append(message);

  uint64_t length = std::numeric_limits<uint64_t>::max() - 8;
  uint32_t count = 0;
  bool overflowed = stream.extractMessageRange<Message>(length, count, 1);

  EXPECT_TRUE(suite, overflowed);
  EXPECT_EQ(suite, count, uint32_t(0));
}

static void testAegisEncryptDecryptAndLayout(TestSuite& suite)
{
  AegisStream stream;
  stream.secret = (uint128_t(0x0123456789abcdefULL) << 64) | uint128_t(0xfedcba9876543210ULL);

  String plaintext("abcdefgh"_ctv);
  stream.encrypt(plaintext);

  const uint32_t expectedMessageSize = roundUpTo16(40u + uint32_t(plaintext.size()));
  EXPECT_EQ(suite, stream.wBuffer.outstandingBytes(), uint64_t(expectedMessageSize));

  AegisMessage *message = reinterpret_cast<AegisMessage *>(stream.wBuffer.pHead());
  EXPECT_EQ(suite, message->size, expectedMessageSize);

  uint32_t encryptedDataSize = 0;
  std::memcpy(&encryptedDataSize, message->args, sizeof(encryptedDataSize));
  EXPECT_EQ(suite, encryptedDataSize, uint32_t(16 + plaintext.size()));

  String decrypted;
  EXPECT_TRUE(suite, stream.decrypt(message, decrypted));
  EXPECT_STRING_EQ(suite, decrypted, plaintext);
}

static void testAegisMalformedFramesAndTimestampSidecar(TestSuite& suite)
{
  constexpr uint128_t secret = (uint128_t(0x0f1e2d3c4b5a6978ULL) << 64) | uint128_t(0x8877665544332211ULL);

  AegisStream malformed;
  malformed.secret = secret;
  String shortPlaintext("abcdefgh"_ctv);
  malformed.encrypt(shortPlaintext);

  AegisMessage *invalidMessage = reinterpret_cast<AegisMessage *>(malformed.wBuffer.pHead());
  uint32_t invalidEncryptedSize = invalidMessage->size;
  std::memcpy(invalidMessage->args, &invalidEncryptedSize, sizeof(invalidEncryptedSize));

  String decrypted("stale"_ctv);
  EXPECT_FALSE(suite, malformed.decrypt(invalidMessage, decrypted));
  EXPECT_EQ(suite, decrypted.size(), uint64_t(0));

  String frameOne = makeEncryptedFrame(secret, String("frame-one"_ctv));
  String frameTwo = makeEncryptedFrame(secret, String("frame-two"_ctv));
  String frameThree = makeEncryptedFrame(secret, String("frame-three"_ctv));

  AegisStream stream;
  stream.secret = secret;
  stream.rBuffer.append(frameOne);
  stream.rBuffer.append(frameTwo);
  stream.rBuffer.append(frameThree.data(), 8);

  EXPECT_TRUE(suite, stream.stampQueuedInboundMessages());
  EXPECT_EQ(suite, stream.pendingInboundQueuedTimestamps(), uint32_t(2));
  EXPECT_TRUE(suite, stream.stampQueuedInboundMessages());
  EXPECT_EQ(suite, stream.pendingInboundQueuedTimestamps(), uint32_t(2));

  stream.consumeHeadMessage<AegisMessage>();
  EXPECT_TRUE(suite, stream.stampQueuedInboundMessages());
  EXPECT_EQ(suite, stream.pendingInboundQueuedTimestamps(), uint32_t(1));

  int64_t queuedAtNs = 0;
  EXPECT_TRUE(suite, stream.popInboundQueuedTimestamp(queuedAtNs));
  EXPECT_FALSE(suite, stream.popInboundQueuedTimestamp(queuedAtNs));
}

static void testAegisHelpersAndReset(TestSuite& suite)
{
  AuxTFOStream stream;
  stream.secret = (uint128_t(0x1111222233334444ULL) << 64) | uint128_t(0x5555666677778888ULL);
  stream.service = 0x0123456789abcdefULL;
  stream.role = ServiceRole::advertiser;
  stream.aux = String("aux"_ctv);

  String tfoData = stream.generateTFOData();
  EXPECT_EQ(suite, tfoData.size(), uint64_t(sizeof(uint64_t) + stream.aux.size()));

  uint64_t hash = 0;
  std::memcpy(&hash, tfoData.data(), sizeof(hash));
  EXPECT_EQ(suite, hash, AegisStream::generateSecretServiceHash(stream.secret, stream.service));
  EXPECT_TRUE(suite, std::memcmp(tfoData.data() + sizeof(hash), stream.aux.data(), stream.aux.size()) == 0);

  for (int64_t value = 0; value < 1030; ++value)
  {
    stream.inboundQueuedAtNs.push_back(value);
  }
  stream.inboundQueuedAtHead = AegisStream::inboundQueuedAtCompactHeadThreshold;
  stream.compactInboundQueuedTimestampsIfNeeded();

  EXPECT_EQ(suite, stream.inboundQueuedAtHead, uint32_t(0));
  EXPECT_EQ(suite, stream.inboundQueuedAtNs.size(), size_t(1030 - AegisStream::inboundQueuedAtCompactHeadThreshold));
  EXPECT_EQ(suite, stream.inboundQueuedAtNs[0], int64_t(AegisStream::inboundQueuedAtCompactHeadThreshold));

  stream.pendingBuffer.append("pending", 7);
  stream.reset();
  EXPECT_EQ(suite, stream.pendingBuffer.size(), uint64_t(0));
  EXPECT_EQ(suite, stream.pendingInboundQueuedTimestamps(), uint32_t(0));
  EXPECT_TRUE(suite, stream.secret == 0);
  EXPECT_EQ(suite, stream.service, uint64_t(0));
  EXPECT_TRUE(suite, stream.role == ServiceRole::none);
}

} // namespace

int main()
{
  TestSuite suite;

  testStreamBufferPreservesHeadAcrossGrowth(suite);
  testStreamBufferDoesNotReplayQueuedBytesAfterGrowth(suite);
  testCleartextFramingAndRangeExtraction(suite);
  testPartialAndMalformedHeadersFailClosed(suite);
  testExtractMessageRangeReportsOverflow(suite);
  testAegisEncryptDecryptAndLayout(suite);
  testAegisMalformedFramesAndTimestampSidecar(suite);
  testAegisHelpersAndReset(suite);

  return suite.finish("stream tests");
}
