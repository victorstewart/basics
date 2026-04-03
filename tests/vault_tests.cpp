// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "services/vault.h"

namespace {

static int countIPSubjectAltNames(X509 *cert)
{
  if (cert == nullptr)
  {
    return 0;
  }

  GENERAL_NAMES *names = reinterpret_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (names == nullptr)
  {
    return 0;
  }

  int count = 0;
  int nameCount = sk_GENERAL_NAME_num(names);
  for (int index = 0; index < nameCount; ++index)
  {
    GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
    if (name != nullptr && name->type == GEN_IPADD)
    {
      ++count;
    }
  }

  GENERAL_NAMES_free(names);
  return count;
}

static String subjectFieldByNid(X509 *cert, int nid)
{
  String value = {};
  if (cert == nullptr)
  {
    return value;
  }

  X509_NAME *subject = X509_get_subject_name(cert);
  if (subject == nullptr)
  {
    return value;
  }

  char buffer[256] = {};
  int length = X509_NAME_get_text_by_NID(subject, nid, buffer, sizeof(buffer));
  if (length > 0)
  {
    value.assign(buffer, uint32_t(length));
  }

  return value;
}

static bool verifyIssuedCertificate(X509 *leaf, X509 *issuer)
{
  if (leaf == nullptr || issuer == nullptr)
  {
    return false;
  }

  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *context = X509_STORE_CTX_new();
  if (store == nullptr || context == nullptr)
  {
    if (store != nullptr)
    {
      X509_STORE_free(store);
    }
    if (context != nullptr)
    {
      X509_STORE_CTX_free(context);
    }
    return false;
  }

  bool ok = (X509_STORE_add_cert(store, issuer) == 1) &&
            (X509_STORE_CTX_init(context, store, leaf, nullptr) == 1) &&
            (X509_verify_cert(context) == 1);

  X509_STORE_CTX_free(context);
  X509_STORE_free(store);
  return ok;
}

static void testTransportCertificates(TestSuite& suite)
{
  Vault::TransportCertificateOptions options = {};
  options.subjectOrganization = "basics transport"_ctv;
  options.rootCommonName = "basics-transport-root"_ctv;
  options.rootValidityDays = 1095;
  options.nodeValidityDays = 180;

  String rootCertPem = {};
  String rootKeyPem = {};
  String failure = {};
  EXPECT_TRUE(suite, Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, options, &failure));
  EXPECT_TRUE(suite, failure.size() == 0);

  X509 *rootCert = VaultPem::x509FromPem(rootCertPem);
  EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(rootKeyPem);
  EXPECT_TRUE(suite, rootCert != nullptr);
  EXPECT_TRUE(suite, rootKey != nullptr);
  if (rootCert != nullptr)
  {
    EXPECT_EQ(suite, X509_get_signature_nid(rootCert), NID_ED25519);
    EXPECT_STRING_EQ(suite, subjectFieldByNid(rootCert, NID_organizationName), "basics transport"_ctv);
    EXPECT_STRING_EQ(suite, subjectFieldByNid(rootCert, NID_commonName), "basics-transport-root"_ctv);
  }
  if (rootKey != nullptr)
  {
    EXPECT_EQ(suite, EVP_PKEY_base_id(rootKey), EVP_PKEY_ED25519);
  }

  String rootCertRoundTrip = {};
  String rootKeyRoundTrip = {};
  EXPECT_TRUE(suite, VaultPem::x509ToPem(rootCert, rootCertRoundTrip));
  EXPECT_TRUE(suite, VaultPem::privateKeyToPem(rootKey, rootKeyRoundTrip));
  EXPECT_TRUE(suite, rootCertRoundTrip.size() > 0);
  EXPECT_TRUE(suite, rootKeyRoundTrip.size() > 0);

  Vector<String> addresses = {};
  Vault::appendUniqueIPLiteral(addresses, "127.0.0.1"_ctv);
  Vault::appendUniqueIPLiteral(addresses, "::1"_ctv);
  Vault::appendUniqueIPLiteral(addresses, "127.0.0.1"_ctv);
  Vault::appendUniqueIPLiteral(addresses, "not-an-ip"_ctv);
  EXPECT_EQ(suite, addresses.size(), uint32_t(2));

  String nodeCertPem = {};
  String nodeKeyPem = {};
  uint128_t uuid = (uint128_t(0x1234567890abcdefULL) << 64) | uint128_t(0xfedcba0987654321ULL);
  EXPECT_TRUE(suite, Vault::generateTransportNodeCertificateEd25519(
                         rootCertPem,
                         rootKeyPem,
                         uuid,
                         addresses,
                         nodeCertPem,
                         nodeKeyPem,
                         options,
                         &failure));
  EXPECT_TRUE(suite, failure.size() == 0);

  X509 *nodeCert = VaultPem::x509FromPem(nodeCertPem);
  EVP_PKEY *nodeKey = VaultPem::privateKeyFromPem(nodeKeyPem);
  EXPECT_TRUE(suite, nodeCert != nullptr);
  EXPECT_TRUE(suite, nodeKey != nullptr);
  if (nodeCert != nullptr)
  {
    EXPECT_EQ(suite, X509_get_signature_nid(nodeCert), NID_ED25519);
    EXPECT_EQ(suite, countIPSubjectAltNames(nodeCert), 2);
    EXPECT_STRING_EQ(suite, subjectFieldByNid(nodeCert, NID_organizationName), "basics transport"_ctv);
  }
  if (nodeKey != nullptr)
  {
    EXPECT_EQ(suite, EVP_PKEY_base_id(nodeKey), EVP_PKEY_ED25519);
  }
  EXPECT_TRUE(suite, verifyIssuedCertificate(nodeCert, rootCert));

  uint128_t extractedUUID = 0;
  EXPECT_TRUE(suite, Vault::extractTransportCertificateUUID(nodeCert, extractedUUID));
  EXPECT_TRUE(suite, extractedUUID == uuid);

  uint128_t parsedUUID = 0;
  String commonName = {};
  EXPECT_TRUE(suite, Vault::buildNodeCommonName(uuid, commonName));
  EXPECT_TRUE(suite, Vault::parseNodeCommonName(commonName, parsedUUID));
  EXPECT_TRUE(suite, parsedUUID == uuid);

  String invalidNodeCertPem = {};
  String invalidNodeKeyPem = {};
  EXPECT_FALSE(suite, Vault::generateTransportNodeCertificateEd25519(
                          ""_ctv,
                          ""_ctv,
                          uuid,
                          addresses,
                          invalidNodeCertPem,
                          invalidNodeKeyPem,
                          options,
                          &failure));
  EXPECT_STRING_EQ(suite, failure, "invalid transport root material"_ctv);

  if (rootCert != nullptr)
  {
    X509_free(rootCert);
  }
  if (rootKey != nullptr)
  {
    EVP_PKEY_free(rootKey);
  }
  if (nodeCert != nullptr)
  {
    X509_free(nodeCert);
  }
  if (nodeKey != nullptr)
  {
    EVP_PKEY_free(nodeKey);
  }
}

static void testSSHEd25519KeyPackages(TestSuite& suite)
{
  Vault::SSHKeyPackage package = {};
  String failure = {};
  EXPECT_TRUE(suite, Vault::generateSSHKeyPackageEd25519(package, "vault-test@basics"_ctv, &failure));
  EXPECT_TRUE(suite, failure.size() == 0);

  std::string_view privateKey = stringViewOf(package.privateKeyOpenSSH);
  std::string_view publicKey = stringViewOf(package.publicKeyOpenSSH);
  EXPECT_TRUE(suite, privateKey.find("BEGIN OPENSSH PRIVATE KEY") != std::string_view::npos);
  EXPECT_TRUE(suite, privateKey.find("END OPENSSH PRIVATE KEY") != std::string_view::npos);
  EXPECT_TRUE(suite, publicKey.rfind("ssh-ed25519 ", 0) == 0);
  EXPECT_TRUE(suite, publicKey.find("vault-test@basics") != std::string_view::npos);
  EXPECT_TRUE(suite, Vault::validateSSHKeyPackageEd25519(package, &failure));
  EXPECT_TRUE(suite, failure.size() == 0);

  Vault::SSHKeyPackage tamperedPublic = package;
  size_t publicPayloadStart = publicKey.find(' ');
  if (publicPayloadStart != std::string_view::npos && publicPayloadStart + 1 < tamperedPublic.publicKeyOpenSSH.size())
  {
    uint8_t *byte = tamperedPublic.publicKeyOpenSSH.data() + publicPayloadStart + 1;
    *byte = (*byte == 'A') ? 'B' : 'A';
  }
  EXPECT_FALSE(suite, Vault::validateSSHKeyPackageEd25519(tamperedPublic, &failure));

  Vault::SSHKeyPackage tamperedPrivate = package;
  std::string_view tamperedPrivateView = stringViewOf(tamperedPrivate.privateKeyOpenSSH);
  size_t bodyOffset = tamperedPrivateView.find('\n');
  if (bodyOffset != std::string_view::npos && bodyOffset + 1 < tamperedPrivate.privateKeyOpenSSH.size())
  {
    uint8_t *byte = tamperedPrivate.privateKeyOpenSSH.data() + bodyOffset + 1;
    *byte = (*byte == 'A') ? 'B' : 'A';
  }
  EXPECT_FALSE(suite, Vault::validateSSHKeyPackageEd25519(tamperedPrivate, &failure));

  Vault::SSHKeyPackage invalidComment = {};
  EXPECT_FALSE(suite, Vault::generateSSHKeyPackageEd25519(invalidComment, String("bad\ncomment"), &failure));
  EXPECT_STRING_EQ(suite, failure, "ssh ed25519 key comment must be single-line text"_ctv);
}

} // namespace

int main()
{
  TestSuite suite;

  testTransportCertificates(suite);
  testSSHEd25519KeyPackages(suite);

  return suite.finish("vault tests");
}
