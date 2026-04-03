// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "tests/test_support.h"

#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include "networking/tls.h"

namespace tls_test_support {

struct TLSMaterial {
  std::string chain;
  std::string cert;
  std::string key;
};

inline std::string fixturePath(std::string_view name)
{
  return std::string(BASICS_TESTS_SOURCE_DIR) + "/fixtures/tls/" + std::string(name);
}

inline std::string readFixture(std::string_view name)
{
  std::ifstream input(fixturePath(name), std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline TLSMaterial readPeerMaterial(std::string_view stem)
{
  return {
      readFixture("ca.cert.pem"),
      readFixture(std::string(stem) + ".cert.pem"),
      readFixture(std::string(stem) + ".key.pem")};
}

inline void freeCtx(SSL_CTX *&context)
{
  if (context != nullptr)
  {
    SSL_CTX_free(context);
    context = nullptr;
  }
}

inline bool ensureTailCapacity(Buffer& buffer, uint64_t moreBytes)
{
  if (buffer.remainingCapacity() >= moreBytes)
  {
    return true;
  }

  return buffer.reserve(buffer.size() + moreBytes);
}

inline bool pumpTLS(TLSBase& sender, Buffer& senderBuffer, TLSBase& receiver, Buffer& receiverBuffer, bool& madeProgress)
{
  if (sender.encryptInto(senderBuffer) == false)
  {
    return false;
  }

  uint32_t pending = static_cast<uint32_t>(senderBuffer.outstandingBytes());
  if (pending == 0)
  {
    return true;
  }

  if (ensureTailCapacity(receiverBuffer, pending) == false)
  {
    return false;
  }

  std::memcpy(receiverBuffer.pTail(), senderBuffer.pHead(), pending);

  if (receiver.decryptFrom(receiverBuffer, pending) == false)
  {
    return false;
  }

  sender.noteEncryptedBytesSent(pending);
  senderBuffer.consume(pending, true);
  madeProgress = true;
  return true;
}

inline bool negotiateTLS(
    TLSBase& client,
    Buffer& clientWire,
    Buffer& clientPlain,
    TLSBase& server,
    Buffer& serverWire,
    Buffer& serverPlain,
    int rounds = 16)
{
  for (int round = 0; round < rounds; ++round)
  {
    bool madeProgress = false;
    if (pumpTLS(client, clientWire, server, serverPlain, madeProgress) == false)
    {
      return false;
    }

    if (pumpTLS(server, serverWire, client, clientPlain, madeProgress) == false)
    {
      return false;
    }

    if (client.isTLSNegotiated() && server.isTLSNegotiated())
    {
      return true;
    }

    if (madeProgress == false)
    {
      break;
    }
  }

  return false;
}

inline String makeDeterministicPayload(uint32_t payloadBytes)
{
  String payload(payloadBytes, MemoryType::heap);
  if (payloadBytes == 0)
  {
    return payload;
  }

  payload.resize(payloadBytes);
  for (uint32_t index = 0; index < payloadBytes; ++index)
  {
    payload.data()[index] = static_cast<uint8_t>((index * 131u + 17u) & 0xffu);
  }

  return payload;
}

} // namespace tls_test_support
