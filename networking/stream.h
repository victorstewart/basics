// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <services/crypto.h>
#include <base/traits.h>
#include <networking/socket.h>
#include <cstring>
#include <limits>
#include <time.h>

#pragma once

class StreamBuffer : public Buffer {
private:

  Buffer other;
  bool isBase = true;
  bool sendInFlight = false;
  bool sendSourceIsBase = true;

  void swap(void)
  {
    Buffer temp = std::move(*this);
    *static_cast<Buffer *>(this) = std::move(other);
    other = std::move(temp);
  }

public:

  // any reserve operation... we catch and then swap the guts

  void reset(void)
  {
    Buffer::reset();
    other.reset();
    isBase = true;
    sendInFlight = false;
    sendSourceIsBase = true;
  }

  void clear(void)
  {
    Buffer::clear();
    other.clear();
    isBase = true;
    sendInFlight = false;
    sendSourceIsBase = true;
  }

  virtual bool reserve(uint64_t newCapacity, uint64_t lengthToCopy = 0)
  {
    // capacity > 0 because allow the first reservation
    if (capacity > 0 && newCapacity > capacity)
    {
      // If the inactive mirror currently owns the in-flight send bytes, the
      // active buffer can grow in-place safely.
      if (sendInFlight && (sendSourceIsBase != isBase))
      {
        return Buffer::reserve(newCapacity, lengthToCopy);
      }

      const uint64_t preservedHead = head;
      other.clear();
      other.reserve(newCapacity);

      if (length > 0)
      {
        other.append(string, length);
      }

      // Preserve logical consume position when mirroring into the expansion buffer.
      // We copy full bytes (not only outstanding) to keep in-progress message
      // header offsets valid, but head must track the same consumed prefix.
      other.head = preservedHead;
      length = 0;
      head = 0;

      swap();
      isBase = !isBase;

      return true;
    }
    else
    {
      return Buffer::reserve(newCapacity, lengthToCopy);
    }
  }

  virtual void consume(uint64_t count, bool zeroIfConsumed)
  {
    Buffer::consume(count, zeroIfConsumed);

    if (isBase == false)
    {
      const bool inactiveMirrorOwnsInFlightSend = sendInFlight && (sendSourceIsBase != isBase);
      if (length == 0 && inactiveMirrorOwnsInFlightSend == false)
      {
        // The inactive mirror can hold stale bytes from a prior growth-under-send
        // window. If we swap while those bytes remain, we can resurrect old frames.
        other.clear();
        swap();
        isBase = true;
      }
    }
  }

  void noteSendQueued(void)
  {
    sendInFlight = true;
    sendSourceIsBase = isBase;
  }

  void noteSendCompleted(void)
  {
    sendInFlight = false;
  }
};

class StreamBase {
public:

  StreamBuffer rBuffer;
  StreamBuffer wBuffer;

  virtual void reset(void)
  {
    rBuffer.reset();
    wBuffer.reset();
  }

  virtual uint32_t nBytesToSend(void)
  {
    return wBuffer.outstandingBytes(); // TLSStream will override this to return the number of encrypted bytes at the head
  }

  virtual uint8_t *pBytesToSend(void)
  {
    return wBuffer.pHead();
  }

  virtual uint64_t queuedSendOutstandingBytes(void) const
  {
    return wBuffer.outstandingBytes();
  }

  virtual void consumeSentBytes(uint32_t count, bool zeroIfConsumed)
  {
    wBuffer.consume(count, zeroIfConsumed);
  }

  virtual void noteSendQueued(void)
  {
    wBuffer.noteSendQueued();
  }

  virtual void noteSendCompleted(void)
  {
    wBuffer.noteSendCompleted();
  }

  virtual void clearQueuedSendBytes(void)
  {
    wBuffer.clear();
  }
};

class Stream : public StreamBase {
public:

  virtual void reset(void)
  {
    StreamBase::reset();
  }

  template <typename MessageType, typename Dispatch>
  bool extractMessages(Dispatch&& dispatch, bool consumeAfterDispatch, uint32_t maxCount, uint32_t minSize, uint32_t maxSize, bool& failed)
  {
    failed = false;
    bool stop = false;

    uint8_t *head = rBuffer.pHead();
    uint8_t *terminal = rBuffer.pTail();

    while ((terminal - head) >= static_cast<ptrdiff_t>(sizeof(uint32_t))) // the size is first and is 4 bytes
    {
      uint32_t messageSize = 0;
      memcpy(&messageSize, head, sizeof(messageSize));
      MessageType *message = reinterpret_cast<MessageType *>(head);
      const uint64_t availableBytes = static_cast<uint64_t>(terminal - head);

      // Validate the common wire-size invariant first.
      if (unlikely(messageSize < minSize || messageSize > maxSize))
      {
        failed = true;
        break;
      }

      // Apply header/padding invariants only for message types that expose
      // those fields (normal Message) and skip for compact wrappers
      // (AegisMessage).
      if constexpr (requires (MessageType *m) { m->padding; })
      {
        constexpr uint32_t wireHeaderBytes = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);

        if (availableBytes < wireHeaderBytes)
        {
          rBuffer.reserve(messageSize);
          break;
        }

        if (unlikely(message->padding > message->size))
        {
          failed = true;
          break;
        }
      }

      if constexpr (requires (MessageType *m) { m->headerSize; })
      {
        constexpr uint32_t wireHeaderBytes = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);

        // Corrupt header fields (especially padding/headerSize) can make
        // payload pointer arithmetic wrap and poison downstream writers.
        if (unlikely(
                message->size < wireHeaderBytes ||
                message->headerSize < wireHeaderBytes ||
                message->headerSize > message->size))
        {
          failed = true;
          break;
        }

        if constexpr (requires (MessageType *m) { m->padding; })
        {
          if (unlikely(message->headerSize > (message->size - message->padding)))
          {
            failed = true;
            break;
          }
        }
      }

      if (messageSize > availableBytes)
      {
        rBuffer.reserve(messageSize);
        break;
      }

      if constexpr (callable_traits<Dispatch>::nargs == 2)
      {
        dispatch(message, stop);
      }
      else
      {
        dispatch(message);
      }

      if (consumeAfterDispatch)
      {
        rBuffer.consume(messageSize, true);
        head = rBuffer.pHead();
        terminal = rBuffer.pTail();
      }
      else
      {
        head += messageSize;
      }

      if (stop || --maxCount == 0)
      {
        break;
      }
    }

    return false;
  }

  template <typename MessageType, typename Dispatch>
  void extractMessagesUnsafe(Dispatch&& dispatch)
  {
    bool failed;
    extractMessages<MessageType>(std::forward<Dispatch>(dispatch), true, UINT32_MAX, 16, UINT32_MAX, failed);
  }

  template <typename MessageType>
  bool extractMessageRange(uint64_t& length, uint32_t& count, uint32_t maxCount) // only intra-datacenter non-failable
  {
    // when we're handling messages 1 at a time, we can let it overflow into for us, but not when we extract ranges

    bool failed = false;
    bool willOverflow = false;
    extractMessages<MessageType>([&](MessageType *message, bool& stop) -> void {
      if (length > (std::numeric_limits<uint64_t>::max() - message->size))
      {
        willOverflow = true;
        stop = true;
        return;
      }

      length += message->size;
      ++count;
    },
                                                     false, maxCount, 16, UINT32_MAX, failed);

    return willOverflow;
  }

  // unless you consume the messages, this doesn't work
  template <typename MessageType>
  MessageType *hasMessage(uint32_t minSize, uint32_t maxSize, bool& failed)
  {
    MessageType *message = nullptr;

    extractMessages<MessageType>([&](MessageType *_message) -> void {
      message = _message;
    },
                                 false, 1, minSize, maxSize, failed);

    return message;
  }

  template <typename MessageType>
  void consumeHeadMessage(void)
  {
    MessageType *message = (MessageType *)rBuffer.pHead();
    rBuffer.consume(message->size, true);
  }
};

class TCPStream : public Stream, public TCPSocket {
public:

  void reset(void)
  {
    Stream::reset();
    TCPSocket::reset();
  }
};

class UnixStream : public Stream, public UnixSocket {
public:

  void setUnixPairHalf(int _fd)
  {
    isPair = true;
    fd = _fd;
  }

  void reset(void)
  {
    Stream::reset();
    UnixSocket::reset();
  }
};

enum class ServiceRole : uint8_t {

  none,
  advertiser,
  subscriber
};

#include <aegis/aegis.h>
#include <aegis/aegis128l.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
struct AegisMessage {

  static constexpr uint32_t headerBytes = 20;

  uint32_t size;
  uint8_t nonce[16];
  uint8_t args[];

  // alignof(AegisMessage) = 4
  // sizeof(AegisMessage) = 20
};
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

class AegisStream : public TCPStream {
public:

  uint128_t secret;
  uint64_t service;
  ServiceRole role;
  Buffer pendingBuffer;
  Vector<int64_t> inboundQueuedAtNs;
  uint32_t inboundQueuedAtHead = 0;

  static inline uint32_t minMessageSize = 48; // size(4) nonce(16) message{4} [message is at least 24 bytes, 16 for the authenication header plus 8 for an echo]
  static inline uint32_t maxMessageSize = 2 * 1024 * 1024;
  static inline uint32_t inboundQueuedAtCompactHeadThreshold = 1024;

  static int64_t monotonicNowNs(void)
  {
    struct timespec ts = {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t(ts.tv_sec) * 1'000'000'000LL) + int64_t(ts.tv_nsec);
  }

  uint32_t pendingInboundQueuedTimestamps(void) const
  {
    if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
    {
      return 0;
    }

    return uint32_t(inboundQueuedAtNs.size() - inboundQueuedAtHead);
  }

  void compactInboundQueuedTimestampsIfNeeded(void)
  {
    if (inboundQueuedAtHead == 0)
    {
      return;
    }

    if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
    {
      inboundQueuedAtNs.clear();
      inboundQueuedAtHead = 0;
      return;
    }

    if (inboundQueuedAtHead < inboundQueuedAtCompactHeadThreshold &&
        (inboundQueuedAtHead * 2) < inboundQueuedAtNs.size())
    {
      return;
    }

    Vector<int64_t> compacted;
    compacted.reserve(inboundQueuedAtNs.size() - inboundQueuedAtHead);

    for (uint32_t index = inboundQueuedAtHead; index < inboundQueuedAtNs.size(); index++)
    {
      compacted.push_back(inboundQueuedAtNs[index]);
    }

    inboundQueuedAtNs = std::move(compacted);
    inboundQueuedAtHead = 0;
  }

  static uint64_t generateSecretServiceHash(uint128_t secret, uint64_t service)
  {
    uint8_t input[24];

    memcpy(input, (uint8_t *)&secret, 16);
    memcpy(input + 16, (uint8_t *)&service, 8);

    // Pairing hash must be stable across processes/threads.
    // Hasher::hash is intentionally per-thread random-seeded, so use gxhash64 with a fixed seed here.
    constexpr int64_t pairingHashSeed = 0x4d595df4d0f33173LL;
    return gxhash64(input, sizeof(input), pairingHashSeed);
  }

  virtual String generateAuxTFOData(void)
  {
    return String();
  }

  String generateTFOData(void)
  {
    String tfoData;
    tfoData.append(AegisStream::generateSecretServiceHash(secret, service));
    tfoData.append(generateAuxTFOData());
    return tfoData;
  }

  void reset(void)
  {
    secret = 0;
    service = 0;
    role = ServiceRole::none;
    pendingBuffer.clear();
    inboundQueuedAtNs.clear();
    inboundQueuedAtHead = 0;

    TCPStream::reset();
  }

  bool popInboundQueuedTimestamp(int64_t& queuedAtNs)
  {
    if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
    {
      return false;
    }

    queuedAtNs = inboundQueuedAtNs[inboundQueuedAtHead++];
    compactInboundQueuedTimestampsIfNeeded();
    return true;
  }

  bool stampQueuedInboundMessages(void)
  {
    bool failed = false;
    uint32_t completeMessagesNow = 0;

    extractMessages<AegisMessage>([&](AegisMessage *) -> void {
      completeMessagesNow += 1;
    },
                                  false, UINT32_MAX, minMessageSize, maxMessageSize, failed);

    if (failed)
    {
      return false;
    }

    uint32_t stampedMessages = pendingInboundQueuedTimestamps();

    if (completeMessagesNow > stampedMessages)
    {
      uint32_t toStamp = completeMessagesNow - stampedMessages;
      int64_t queuedAtNs = monotonicNowNs();

      for (uint32_t index = 0; index < toStamp; index++)
      {
        inboundQueuedAtNs.push_back(queuedAtNs);
      }
    }
    else if (stampedMessages > completeMessagesNow)
    {
      // Keep sidecar timestamps aligned if some queued frames were consumed
      // before this receive cycle sampled completion.
      uint32_t toDrop = stampedMessages - completeMessagesNow;
      inboundQueuedAtHead += toDrop;
      compactInboundQueuedTimestampsIfNeeded();
    }

    return true;
  }

  bool decrypt(AegisMessage *message, String& plaintext)
  {
    constexpr uint32_t aegisWireHeaderBytes = sizeof(AegisMessage) + sizeof(uint32_t);

    uint8_t *cursor = message->args;

    // these are de facto aligned
    uint32_t encryptedDataSize = *(uint32_t *)cursor;
    cursor += sizeof(uint32_t);

    if (message->size < aegisWireHeaderBytes)
    {
      plaintext.resize(0);
      return false;
    }

    const uint32_t maxEncryptedDataSize = message->size - aegisWireHeaderBytes;
    if (encryptedDataSize < 16 || encryptedDataSize > maxEncryptedDataSize)
    {
      plaintext.resize(0);
      return false;
    }

    uint8_t *encryptedData = cursor;
    uint32_t plaintextSize = encryptedDataSize - 16;

    plaintext.resize(0);
    plaintext.reserve(plaintextSize);

    if (aegis128l_decrypt(plaintext.data(), encryptedData, encryptedDataSize, 16, (uint8_t *)&message->size, 4, message->nonce, (uint8_t *)&secret) == 0)
    {
      plaintext.resize(plaintextSize);
      return true;
    }

    plaintext.resize(0);
    return false;
  }

  void encrypt(const StringDescendent auto& plaintext)
  {
    uint128_t nonce = Crypto::secureRandomNumber<uint128_t>();

    uint32_t plaintextSize = uint32_t(plaintext.pTail() - plaintext.pHead());

    uint32_t encryptedDataSize = 16 + plaintextSize; // encrypted messsage is the same number of bytes as the plaintext, we just add 16 for the authentication tag

    // start 16 byte aligned
    // 4 bytes for size + 16 bytes for nonce + 4 bytes for size of encrypted message + encryptedDataSize
    uint32_t messageSize = 4 + 16 + 4 + encryptedDataSize;
    uint32_t padding = (16 - (messageSize % 16)) % 16; // pad it to multiple of 16 so its 16 byte aligned
    messageSize += padding;

    if (wBuffer.need(messageSize) == false)
    {
      return;
    }

    // As long as the nonce is not reused, it is impossible to recover the AEGIS state and key faster than exhaustive key search (under the assumption that a 128-bit authentication tag is used, and the forgery attack cannot be repeated for the same key for more than 2^128 times).

    // https://lemire.me/blog/2018/09/07/avx-512-when-and-how-to-use-these-new-instructions/
    // Dr Ian Cutress tested various AVX usages on Zen4 and both power and performance benefited with AVX512 with an exception that lost about 5%. He was impressed with the lack of downsides.
    // https://travisdowns.github.io/blog/2020/08/19/icl-avx512-freq.html

    // we'll put a conditional in here to switch between aegis-128l and aegis-128x2 at runtime depending on cpu capabilties

    // size(4) nonce(16) encryptedData{4}
    wBuffer.append(messageSize); // every message before would be 16 byte aligned
    wBuffer.append((const uint8_t *)&nonce, 16);
    wBuffer.append(encryptedDataSize); // already 4 byte aligned

    aegis128l_encrypt(wBuffer.pTail(), 16, plaintext.pHead(), plaintextSize, (const uint8_t *)&messageSize, 4, (const uint8_t *)&nonce, (const uint8_t *)&secret);
    wBuffer.advance(encryptedDataSize);

    if (padding > 0)
    {
      memset(wBuffer.pTail(), 0, padding);
      wBuffer.advance(padding); // pad to 16
    }
  }
};
