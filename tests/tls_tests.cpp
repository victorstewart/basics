// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"
#include "tests/tls_support.h"

#include <string>
#include <string_view>

#include <openssl/x509.h>

#include "networking/tls.h"

namespace {
using tls_test_support::ensureTailCapacity;
using tls_test_support::fixturePath;
using tls_test_support::freeCtx;
using tls_test_support::negotiateTLS;
using tls_test_support::pumpTLS;
using tls_test_support::readPeerMaterial;
using tls_test_support::TLSMaterial;

static void clearBasicsCtx()
{
  if (TLSBase::basicsCtx != nullptr)
  {
    SSL_CTX_free(TLSBase::basicsCtx);
    TLSBase::basicsCtx = nullptr;
  }
}

static std::string peerCommonName(X509 *certificate)
{
  char commonName[256] = {0};
  X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName, commonName, sizeof(commonName));
  return std::string(commonName);
}

static void testContextLoadingAndStaticConfiguration(TestSuite& suite)
{
  TLSMaterial peerA = readPeerMaterial("peer-a");
  EXPECT_FALSE(suite, peerA.cert.empty());
  EXPECT_FALSE(suite, peerA.key.empty());

  SSL_CTX *fileContext = TLSBase::generateCtx(
      fixturePath("ca.cert.pem").c_str(),
      fixturePath("peer-a.cert.pem").c_str(),
      fixturePath("peer-a.key.pem").c_str());
  EXPECT_TRUE(suite, fileContext != nullptr);
  freeCtx(fileContext);

  SSL_CTX *missingContext = TLSBase::generateCtx(
      fixturePath("does-not-exist.pem").c_str(),
      fixturePath("peer-a.cert.pem").c_str(),
      fixturePath("peer-a.key.pem").c_str());
  EXPECT_TRUE(suite, missingContext == nullptr);

  uint32_t tooLargePem = static_cast<uint32_t>(std::numeric_limits<int>::max()) + 1u;

  SSL_CTX *pemContext = TLSBase::generateCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.key.data(), static_cast<uint32_t>(peerA.key.size()));
  EXPECT_TRUE(suite, pemContext != nullptr);
  freeCtx(pemContext);

  SSL_CTX *badPemContext = TLSBase::generateCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()));
  EXPECT_TRUE(suite, badPemContext == nullptr);

  EXPECT_TRUE(suite, TLSBase::generateCtxFromPEM(nullptr, 0, nullptr, 0, nullptr, 0) == nullptr);
  EXPECT_TRUE(suite, TLSBase::generateCtxFromPEM(
      peerA.chain.data(), tooLargePem,
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.key.data(), static_cast<uint32_t>(peerA.key.size())) == nullptr);

  clearBasicsCtx();
  EXPECT_TRUE(suite, TLSBase::configureBasicsCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.key.data(), static_cast<uint32_t>(peerA.key.size())));
  EXPECT_TRUE(suite, TLSBase::basicsCtx != nullptr);

  SSL_CTX *configured = TLSBase::basicsCtx;
  EXPECT_FALSE(suite, TLSBase::configureBasicsCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size())));
  EXPECT_TRUE(suite, TLSBase::basicsCtx == configured);
  clearBasicsCtx();
}

static void testHandshakeDataFlowAndReset(TestSuite& suite)
{
  TLSMaterial peerA = readPeerMaterial("peer-a");

  SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.key.data(), static_cast<uint32_t>(peerA.key.size()));
  SSL_CTX *serverContext = TLSBase::generateCtx(
      fixturePath("ca.cert.pem").c_str(),
      fixturePath("peer-a.cert.pem").c_str(),
      fixturePath("peer-a.key.pem").c_str());

  EXPECT_TRUE(suite, clientContext != nullptr);
  EXPECT_TRUE(suite, serverContext != nullptr);
  if (clientContext == nullptr || serverContext == nullptr)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    return;
  }

  TLSBase client(clientContext, false);
  TLSBase server(serverContext, true);

  Buffer clientWire(4096, MemoryType::heap);
  Buffer clientPlain(4096, MemoryType::heap);
  Buffer serverWire(4096, MemoryType::heap);
  Buffer serverPlain(4096, MemoryType::heap);

  EXPECT_TRUE(suite, negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain));
  EXPECT_TRUE(suite, client.isTLSNegotiated());
  EXPECT_TRUE(suite, server.isTLSNegotiated());
  EXPECT_EQ(suite, SSL_get_verify_result(client.ssl), long(X509_V_OK));
  EXPECT_EQ(suite, SSL_get_verify_result(server.ssl), long(X509_V_OK));

  X509 *clientPeer = client.duplicatePeerCertificate();
  X509 *serverPeer = server.duplicatePeerCertificate();
  EXPECT_TRUE(suite, clientPeer != nullptr);
  EXPECT_TRUE(suite, serverPeer != nullptr);
  if (clientPeer != nullptr)
  {
    EXPECT_EQ(suite, peerCommonName(clientPeer), std::string("basics-tls-peer-a"));
    X509_free(clientPeer);
  }
  if (serverPeer != nullptr)
  {
    EXPECT_EQ(suite, peerCommonName(serverPeer), std::string("basics-tls-peer-a"));
    X509_free(serverPeer);
  }

  clientWire.append("hello over tls");
  EXPECT_TRUE(suite, client.encryptInto(clientWire));
  uint32_t encryptedBytes = client.encryptedBytesToSend();
  EXPECT_TRUE(suite, encryptedBytes > 0);
  client.noteEncryptedBytesSent(1);
  EXPECT_EQ(suite, client.encryptedBytesToSend(), encryptedBytes - 1);
  client.noteEncryptedBytesSent(encryptedBytes);
  EXPECT_EQ(suite, client.encryptedBytesToSend(), uint32_t(0));

  uint32_t ciphertextBytes = static_cast<uint32_t>(clientWire.outstandingBytes());
  EXPECT_TRUE(suite, ensureTailCapacity(serverPlain, ciphertextBytes));
  std::memcpy(serverPlain.pTail(), clientWire.pHead(), ciphertextBytes);
  EXPECT_TRUE(suite, server.decryptFrom(serverPlain, ciphertextBytes));
  clientWire.consume(ciphertextBytes, true);
  EXPECT_STRING_EQ(suite, serverPlain, "hello over tls");

  serverWire.append("response payload");
  bool madeProgress = false;
  EXPECT_TRUE(suite, pumpTLS(server, serverWire, client, clientPlain, madeProgress));
  EXPECT_TRUE(suite, madeProgress);
  EXPECT_STRING_EQ(suite, clientPlain, "response payload");

  Buffer preserved(128, MemoryType::heap);
  preserved.append("keep");
  uint8_t invalidRecord[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0xff, 0xff};
  EXPECT_TRUE(suite, ensureTailCapacity(preserved, sizeof(invalidRecord)));
  std::memcpy(preserved.pTail(), invalidRecord, sizeof(invalidRecord));
  EXPECT_FALSE(suite, client.decryptFrom(preserved, sizeof(invalidRecord)));
  EXPECT_STRING_EQ(suite, preserved, "keep");

  client.resetTLS();
  server.resetTLS();
  clientWire.reset();
  clientPlain.reset();
  serverWire.reset();
  serverPlain.reset();
  EXPECT_FALSE(suite, client.isTLSNegotiated());
  EXPECT_FALSE(suite, server.isTLSNegotiated());
  EXPECT_EQ(suite, client.encryptedBytesToSend(), uint32_t(0));
  EXPECT_EQ(suite, server.encryptedBytesToSend(), uint32_t(0));
  EXPECT_TRUE(suite, client.duplicatePeerCertificate() == nullptr);
  EXPECT_TRUE(suite, server.duplicatePeerCertificate() == nullptr);

  freeCtx(clientContext);
  freeCtx(serverContext);
}

static void testVerificationFailureAndNullSetup(TestSuite& suite)
{
  TLSMaterial peerA = readPeerMaterial("peer-a");
  TLSMaterial peerB = readPeerMaterial("peer-b");

  SSL_CTX *clientContext = TLSBase::generateCtxFromPEM(
      peerA.chain.data(), static_cast<uint32_t>(peerA.chain.size()),
      peerA.cert.data(), static_cast<uint32_t>(peerA.cert.size()),
      peerA.key.data(), static_cast<uint32_t>(peerA.key.size()));
  SSL_CTX *serverContext = TLSBase::generateCtxFromPEM(
      peerB.chain.data(), static_cast<uint32_t>(peerB.chain.size()),
      peerB.cert.data(), static_cast<uint32_t>(peerB.cert.size()),
      peerB.key.data(), static_cast<uint32_t>(peerB.key.size()));

  EXPECT_TRUE(suite, clientContext != nullptr);
  EXPECT_TRUE(suite, serverContext != nullptr);
  if (clientContext == nullptr || serverContext == nullptr)
  {
    freeCtx(clientContext);
    freeCtx(serverContext);
    return;
  }

  TLSBase client(clientContext, false);
  TLSBase server(serverContext, true);

  Buffer clientWire(4096, MemoryType::heap);
  Buffer clientPlain(4096, MemoryType::heap);
  Buffer serverWire(4096, MemoryType::heap);
  Buffer serverPlain(4096, MemoryType::heap);

  EXPECT_FALSE(suite, negotiateTLS(client, clientWire, clientPlain, server, serverWire, serverPlain, 16));
  EXPECT_FALSE(suite, client.isTLSNegotiated() && server.isTLSNegotiated());

  TLSBase unconfigured;
  unconfigured.setupTLS(nullptr, false);
  EXPECT_TRUE(suite, unconfigured.ssl == nullptr);
  EXPECT_FALSE(suite, unconfigured.isTLSNegotiated());
  EXPECT_TRUE(suite, unconfigured.duplicatePeerCertificate() == nullptr);

  Buffer untouched(64, MemoryType::heap);
  untouched.append("keep");
  EXPECT_FALSE(suite, unconfigured.encryptInto(untouched));
  EXPECT_STRING_EQ(suite, untouched, "keep");
  EXPECT_TRUE(suite, unconfigured.decryptFrom(untouched, 0));
  EXPECT_STRING_EQ(suite, untouched, "keep");
  EXPECT_FALSE(suite, unconfigured.decryptFrom(untouched, 4));
  EXPECT_STRING_EQ(suite, untouched, "keep");

  unconfigured.destroyTLS();
  unconfigured.destroyTLS();
  EXPECT_TRUE(suite, unconfigured.ssl == nullptr);
  EXPECT_TRUE(suite, unconfigured.duplicatePeerCertificate() == nullptr);

  freeCtx(clientContext);
  freeCtx(serverContext);
}

} // namespace

int main()
{
  TestSuite suite;
  testContextLoadingAndStaticConfiguration(suite);
  testHandshakeDataFlowAndReset(suite);
  testVerificationFailureAndNullSetup(suite);
  return suite.finish("tls_tests");
}
