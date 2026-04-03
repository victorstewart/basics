// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/tls_support.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using tls_test_support::freeCtx;
using tls_test_support::makeDeterministicPayload;
using tls_test_support::negotiateTLS;
using tls_test_support::pumpTLS;
using tls_test_support::readPeerMaterial;
using tls_test_support::TLSMaterial;

volatile uint64_t g_tls_profile_sink = 0;

static void profileConsume(uint64_t value)
{
  g_tls_profile_sink ^= value + 0x4f1bbcdc2c8f1d3bULL;
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

struct Options {

  std::string scenario = "tls-long-lived-session";
  uint32_t iterations = 128;
  uint32_t payloadBytes = 4096;
};

static void printUsage(const char *argv0)
{
  std::cerr
      << "Usage:\n"
      << "  " << argv0 << " --list-scenarios\n"
      << "  " << argv0 << " [--scenario tls-handshake|tls-steady-state|tls-long-lived-session] [--iterations n] [--payload-bytes n]\n";
}

static uint64_t parseUnsigned(const char *flag, const char *value)
{
  if (value == nullptr || value[0] == '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires a value");
  }

  char *terminal = nullptr;
  unsigned long long parsed = std::strtoull(value, &terminal, 10);
  if (terminal == value || terminal == nullptr || *terminal != '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires an unsigned integer");
  }

  return static_cast<uint64_t>(parsed);
}

static Options parseOptions(int argc, char **argv)
{
  Options options;

  for (int index = 1; index < argc; ++index)
  {
    std::string_view argument(argv[index]);
    if (argument == "--scenario")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--scenario requires a value");
      }
      options.scenario = argv[++index];
    }
    else if (argument == "--iterations")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--iterations requires a value");
      }
      options.iterations = static_cast<uint32_t>(parseUnsigned("--iterations", argv[++index]));
      if (options.iterations == 0)
      {
        throw std::runtime_error("--iterations must be greater than 0");
      }
    }
    else if (argument == "--payload-bytes")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--payload-bytes requires a value");
      }
      options.payloadBytes = static_cast<uint32_t>(parseUnsigned("--payload-bytes", argv[++index]));
      if (options.payloadBytes == 0)
      {
        throw std::runtime_error("--payload-bytes must be greater than 0");
      }
    }
    else if (argument == "--list-scenarios")
    {
      std::cout << "tls-handshake\tRepeated TLS handshake over memory BIOs with preloaded contexts.\n";
      std::cout << "tls-steady-state\tRepeated bidirectional encrypted read/write after one negotiated handshake.\n";
      std::cout << "tls-long-lived-session\tOne negotiated session followed by many bidirectional transfers per iteration for denser steady-state profiling.\n";
      std::exit(0);
    }
    else if (argument == "-h" || argument == "--help")
    {
      printUsage(argv[0]);
      std::exit(0);
    }
    else
    {
      throw std::runtime_error("unknown argument: " + std::string(argument));
    }
  }

  return options;
}

static void runHandshakeScenario(const TLSMaterial& material, uint32_t iterations)
{
  SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  if (clientContext == nullptr || serverContext == nullptr)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    throw std::runtime_error("failed to create TLS contexts for handshake scenario");
  }

  for (uint32_t iteration = 0; iteration < iterations; ++iteration)
  {
    TLSBase client(clientContext, false);
    TLSBase server(serverContext, true);
    Buffer clientWire(4096, MemoryType::heap);
    Buffer clientPlain(4096, MemoryType::heap);
    Buffer serverWire(4096, MemoryType::heap);
    Buffer serverPlain(4096, MemoryType::heap);

    if (negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain) == false)
    {
      freeCtx(clientContext);
      freeCtx(serverContext);
      throw std::runtime_error("TLS handshake profile scenario failed to negotiate");
    }

    profileConsume(uint64_t(client.isTLSNegotiated()) + (uint64_t(server.isTLSNegotiated()) << 1));
  }

  freeCtx(clientContext);
  freeCtx(serverContext);
}

static void runSteadyStateScenario(const TLSMaterial& material, uint32_t iterations, uint32_t payloadBytes)
{
  SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  if (clientContext == nullptr || serverContext == nullptr)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    throw std::runtime_error("failed to create TLS contexts for steady-state scenario");
  }

  uint64_t bufferBytes = payloadBytes + 4096u;
  if (bufferBytes < 8192u)
  {
    bufferBytes = 8192u;
  }

  TLSBase client(clientContext, false);
  TLSBase server(serverContext, true);
  Buffer clientWire(bufferBytes, MemoryType::heap);
  Buffer clientPlain(bufferBytes, MemoryType::heap);
  Buffer serverWire(bufferBytes, MemoryType::heap);
  Buffer serverPlain(bufferBytes, MemoryType::heap);
  String payload = makeDeterministicPayload(payloadBytes);

  if (negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain) == false)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    throw std::runtime_error("TLS steady-state profile scenario failed to negotiate");
  }

  for (uint32_t iteration = 0; iteration < iterations; ++iteration)
  {
    bool madeProgress = false;

    clientWire.reset();
    serverPlain.reset();
    clientWire.append(payload.data(), payload.size());
    if (pumpTLS(client, clientWire, server, serverPlain, madeProgress) == false || madeProgress == false)
    {
      freeCtx(clientContext);
      freeCtx(serverContext);
      throw std::runtime_error("TLS steady-state profile client->server transfer failed");
    }
    if (serverPlain.size() != payload.size() || std::memcmp(serverPlain.data(), payload.data(), payload.size()) != 0)
    {
      freeCtx(clientContext);
      freeCtx(serverContext);
      throw std::runtime_error("TLS steady-state profile client->server payload mismatch");
    }

    madeProgress = false;
    serverWire.reset();
    clientPlain.reset();
    serverWire.append(payload.data(), payload.size());
    if (pumpTLS(server, serverWire, client, clientPlain, madeProgress) == false || madeProgress == false)
    {
      freeCtx(clientContext);
      freeCtx(serverContext);
      throw std::runtime_error("TLS steady-state profile server->client transfer failed");
    }
    if (clientPlain.size() != payload.size() || std::memcmp(clientPlain.data(), payload.data(), payload.size()) != 0)
    {
      freeCtx(clientContext);
      freeCtx(serverContext);
      throw std::runtime_error("TLS steady-state profile server->client payload mismatch");
    }

    profileConsume(serverPlain.size() + clientPlain.size());
  }

  freeCtx(clientContext);
  freeCtx(serverContext);
}

static void runLongLivedSessionScenario(const TLSMaterial& material, uint32_t iterations, uint32_t payloadBytes)
{
  SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
      material.chain.data(), static_cast<uint32_t>(material.chain.size()),
      material.cert.data(), static_cast<uint32_t>(material.cert.size()),
      material.key.data(), static_cast<uint32_t>(material.key.size()));
  if (clientContext == nullptr || serverContext == nullptr)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    throw std::runtime_error("failed to create TLS contexts for long-lived session scenario");
  }

  uint64_t bufferBytes = payloadBytes + 4096u;
  if (bufferBytes < 16384u)
  {
    bufferBytes = 16384u;
  }

  TLSBase client(clientContext, false);
  TLSBase server(serverContext, true);
  Buffer clientWire(bufferBytes, MemoryType::heap);
  Buffer clientPlain(bufferBytes, MemoryType::heap);
  Buffer serverWire(bufferBytes, MemoryType::heap);
  Buffer serverPlain(bufferBytes, MemoryType::heap);

  String clientPayload = makeDeterministicPayload(payloadBytes);
  String serverPayload = makeDeterministicPayload(payloadBytes);
  for (uint32_t index = 0; index < serverPayload.size(); ++index)
  {
    serverPayload.data()[index] ^= static_cast<uint8_t>((index * 17u + 29u) & 0xffu);
  }

  if (negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain) == false)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    throw std::runtime_error("TLS long-lived session profile scenario failed to negotiate");
  }

  constexpr uint32_t kRoundTripsPerIteration = 32;
  uint64_t transferredBytes = 0;

  for (uint32_t iteration = 0; iteration < iterations; ++iteration)
  {
    for (uint32_t roundTrip = 0; roundTrip < kRoundTripsPerIteration; ++roundTrip)
    {
      bool madeProgress = false;

      clientWire.reset();
      serverPlain.reset();
      clientWire.append(clientPayload.data(), clientPayload.size());
      if (pumpTLS(client, clientWire, server, serverPlain, madeProgress) == false || madeProgress == false)
      {
        freeCtx(clientContext);
        freeCtx(serverContext);
        throw std::runtime_error("TLS long-lived session profile client->server transfer failed");
      }
      if (serverPlain.size() != clientPayload.size() || std::memcmp(serverPlain.data(), clientPayload.data(), clientPayload.size()) != 0)
      {
        freeCtx(clientContext);
        freeCtx(serverContext);
        throw std::runtime_error("TLS long-lived session profile client->server payload mismatch");
      }
      transferredBytes += serverPlain.size();

      madeProgress = false;
      serverWire.reset();
      clientPlain.reset();
      serverWire.append(serverPayload.data(), serverPayload.size());
      if (pumpTLS(server, serverWire, client, clientPlain, madeProgress) == false || madeProgress == false)
      {
        freeCtx(clientContext);
        freeCtx(serverContext);
        throw std::runtime_error("TLS long-lived session profile server->client transfer failed");
      }
      if (clientPlain.size() != serverPayload.size() || std::memcmp(clientPlain.data(), serverPayload.data(), serverPayload.size()) != 0)
      {
        freeCtx(clientContext);
        freeCtx(serverContext);
        throw std::runtime_error("TLS long-lived session profile server->client payload mismatch");
      }
      transferredBytes += clientPlain.size();
    }

    profileConsume(transferredBytes + uint64_t(client.isTLSNegotiated()) + (uint64_t(server.isTLSNegotiated()) << 1));
  }

  freeCtx(clientContext);
  freeCtx(serverContext);
}

} // namespace

int main(int argc, char **argv)
{
  try
  {
    Options options = parseOptions(argc, argv);
    TLSMaterial material = readPeerMaterial("peer-a");

    if (options.scenario == "tls-handshake")
    {
      runHandshakeScenario(material, options.iterations);
    }
    else if (options.scenario == "tls-steady-state")
    {
      runSteadyStateScenario(material, options.iterations, options.payloadBytes);
    }
    else if (options.scenario == "tls-long-lived-session")
    {
      runLongLivedSessionScenario(material, options.iterations, options.payloadBytes);
    }
    else
    {
      throw std::runtime_error("unsupported scenario: " + options.scenario);
    }
  }
  catch (const std::exception& error)
  {
    std::cerr << "tls profile failed: " << error.what() << '\n';
    return 1;
  }

  return int(g_tls_profile_sink == 0xffffffffffffffffULL);
}
