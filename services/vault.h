// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <arpa/inet.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string_view>

#include <openssl/ec.h> // EVP_EC_gen
#include <openssl/evp.h> // EVP_PKEY_get_raw_public_key, EVP_PKEY_new_raw_public_key
#include <openssl/x509v3.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h> // OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY
#include <openssl/bn.h> // BN_bin2bn
#include <openssl/pem.h>

#include "includes.h"
#include "services/crypto.h"
#include "types/types.containers.h"

#include <openssl/err.h>

enum class CertificateType : uint8_t {

    root,
    intermediary,
    server,
    client
};

enum class CryptoScheme : uint8_t {

    p256,
    ed25519
};

namespace VaultPem
{

static bool x509ToPem(X509 *cert, String& out)
{
    if (cert == nullptr) return false;
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) return false;

    bool ok = (PEM_write_bio_X509(bio, cert) == 1);
    if (ok)
    {
        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        if (data && len > 0)
        {
            out.clear();
            out.append(data, static_cast<uint32_t>(len));
        }
        else
        {
            ok = false;
        }
    }

    BIO_free(bio);
    return ok;
}

static bool privateKeyToPem(EVP_PKEY *key, String& out)
{
    if (key == nullptr) return false;
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) return false;

    bool ok = (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    if (ok)
    {
        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        if (data && len > 0)
        {
            out.clear();
            out.append(data, static_cast<uint32_t>(len));
        }
        else
        {
            ok = false;
        }
    }

    BIO_free(bio);
    return ok;
}

static X509 *x509FromPem(const String& pem)
{
    if (pem.size() == 0) return nullptr;
    BIO *bio = BIO_new_mem_buf(pem.data(), int(pem.size()));
    if (bio == nullptr) return nullptr;

    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

static EVP_PKEY *privateKeyFromPem(const String& pem)
{
    if (pem.size() == 0) return nullptr;
    BIO *bio = BIO_new_mem_buf(pem.data(), int(pem.size()));
    if (bio == nullptr) return nullptr;

    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

}

class VaultCertificateRequest
{
public:

    CertificateType type = CertificateType::server;
    CryptoScheme scheme = CryptoScheme::ed25519;
    String subjectOrganization = {};
    String subjectCommonName = {};
    String subjectAltURI = {};
    bool enableServerAuth = false;
    bool enableClientAuth = false;
    uint32_t validityDays = 0;
};

static bool vaultGenerateKeyPair(CryptoScheme scheme, EVP_PKEY*& privateKey, EVP_PKEY*& publicKey)
{
    privateKey = nullptr;
    publicKey = nullptr;

    switch (scheme)
    {
        case CryptoScheme::p256:
        {
            EVP_PKEY *keypair = EVP_EC_gen("P-256");
            if (keypair == nullptr)
            {
                return false;
            }

            size_t rawkeylen = 0;
            unsigned char rawkey[64] = {};

            auto extractKey = [&] (const char *selectionA, int selectionB) -> EVP_PKEY* {

                EVP_PKEY *key = nullptr;
                if (EVP_PKEY_get_octet_string_param(keypair, selectionA, rawkey, sizeof(rawkey), &rawkeylen) != 1)
                {
                    return nullptr;
                }

                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                if (ctx == nullptr)
                {
                    return nullptr;
                }

                EVP_PKEY *generated = nullptr;
                if (EVP_PKEY_fromdata_init(ctx) == 1)
                {
                    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
                    if (param_bld)
                    {
                        if (std::strcmp(OSSL_PKEY_PARAM_PRIV_KEY, selectionA) == 0 && selectionB == EVP_PKEY_KEYPAIR)
                        {
                            OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", "prime256v1", 0);
                            OSSL_PARAM_BLD_push_octet_string(param_bld, selectionA, rawkey, rawkeylen);
                        }
                        else
                        {
                            OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", "prime256v1", 0);
                            OSSL_PARAM_BLD_push_octet_string(param_bld, selectionA, rawkey, rawkeylen);
                        }

                        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
                        if (params)
                        {
                            if (EVP_PKEY_fromdata(ctx, &generated, selectionB, params) != 1)
                            {
                                if (generated)
                                {
                                    EVP_PKEY_free(generated);
                                    generated = nullptr;
                                }
                            }

                            OSSL_PARAM_free(params);
                        }

                        OSSL_PARAM_BLD_free(param_bld);
                    }
                }

                EVP_PKEY_CTX_free(ctx);
                return generated;
            };

            privateKey = extractKey(OSSL_PKEY_PARAM_PRIV_KEY, EVP_PKEY_KEYPAIR);
            publicKey = extractKey(OSSL_PKEY_PARAM_PUB_KEY, EVP_PKEY_PUBLIC_KEY);
            EVP_PKEY_free(keypair);
            return (privateKey != nullptr && publicKey != nullptr);
        }
        case CryptoScheme::ed25519:
        {
            EVP_PKEY *keypair = nullptr;
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
            if (pctx == nullptr)
            {
                return false;
            }

            bool ok = (EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_keygen(pctx, &keypair) == 1);
            EVP_PKEY_CTX_free(pctx);
            if (ok == false || keypair == nullptr)
            {
                return false;
            }

            size_t rawkeylen = 64;
            unsigned char rawkey[64] = {};
            if (EVP_PKEY_get_raw_public_key(keypair, rawkey, &rawkeylen) != 1)
            {
                EVP_PKEY_free(keypair);
                return false;
            }

            publicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, rawkey, rawkeylen);
            rawkeylen = 64;
            if (EVP_PKEY_get_raw_private_key(keypair, rawkey, &rawkeylen) != 1)
            {
                EVP_PKEY_free(keypair);
                if (publicKey) EVP_PKEY_free(publicKey);
                publicKey = nullptr;
                return false;
            }

            privateKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, rawkey, rawkeylen);
            EVP_PKEY_free(keypair);
            return (privateKey != nullptr && publicKey != nullptr);
        }
    }

    return false;
}

static bool generateCertificateAndKeys(const VaultCertificateRequest& request, X509 *signer, EVP_PKEY *signerPrivateKey, X509*& cert, EVP_PKEY*& privateKey, String *failure = nullptr)
{
    cert = nullptr;
    privateKey = nullptr;
    if (failure) failure->clear();

    if (request.type != CertificateType::root && (signer == nullptr || signerPrivateKey == nullptr))
    {
        if (failure) failure->assign("signer certificate and key required"_ctv);
        return false;
    }

    EVP_PKEY *publicKey = nullptr;
    if (vaultGenerateKeyPair(request.scheme, privateKey, publicKey) == false)
    {
        if (failure) failure->assign("failed to generate key pair"_ctv);
        return false;
    }

    cert = X509_new();
    if (cert == nullptr)
    {
        if (failure) failure->assign("failed to allocate x509"_ctv);
        if (privateKey) EVP_PKEY_free(privateKey);
        if (publicKey) EVP_PKEY_free(publicKey);
        privateKey = nullptr;
        return false;
    }

    X509 *issuerCert = signer;
    EVP_PKEY *issuerKey = signerPrivateKey;
    if (request.type == CertificateType::root)
    {
        issuerCert = cert;
        issuerKey = privateKey;
    }

    bool ok = (X509_set_version(cert, 0x2) == 1);

    uint128_t serialNunber = 0;
    if (ok)
    {
        Crypto::fillWithSecureRandomBytes(reinterpret_cast<uint8_t *>(&serialNunber), sizeof(serialNunber));
        BIGNUM *b_serial = BN_bin2bn((const unsigned char *)&serialNunber, sizeof(serialNunber), NULL);
        if (b_serial == nullptr)
        {
            ok = false;
        }
        else
        {
            ok = (BN_to_ASN1_INTEGER(b_serial, X509_get_serialNumber(cert)) != nullptr);
            BN_free(b_serial);
        }
    }

    if (ok)
    {
        ok = (X509_set_pubkey(cert, publicKey) == 1);
    }

    if (ok)
    {
        ok = (X509_gmtime_adj(X509_getm_notBefore(cert), 0) != nullptr);
    }

    uint32_t validityDays = request.validityDays;
    if (validityDays == 0)
    {
        switch (request.type)
        {
            case CertificateType::root:
            case CertificateType::intermediary:
            {
                validityDays = 3650;
                break;
            }
            case CertificateType::server:
            case CertificateType::client:
            {
                validityDays = 365;
                break;
            }
        }
    }

    if (ok)
    {
        ok = (X509_time_adj_ex(X509_getm_notAfter(cert), int(validityDays), 0, NULL) != nullptr);
    }

    X509_NAME *subject = X509_NAME_new();
    if (subject == nullptr)
    {
        ok = false;
    }

    if (ok && request.subjectOrganization.size() > 0)
    {
        String subjectOrganization = {};
        subjectOrganization.assign(request.subjectOrganization);
        ok = (X509_NAME_add_entry_by_NID(subject, NID_organizationName, MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(subjectOrganization.c_str()), -1, -1, 0) == 1);
    }

    if (ok)
    {
        String commonName = request.subjectCommonName;
        if (commonName.size() == 0)
        {
            switch (request.type)
            {
                case CertificateType::root:
                {
                    commonName.assign("root"_ctv);
                    break;
                }
                case CertificateType::intermediary:
                {
                    commonName.assign("intermediate"_ctv);
                    break;
                }
                case CertificateType::server:
                case CertificateType::client:
                {
                    commonName.assign("leaf"_ctv);
                    break;
                }
            }
        }

        ok = (X509_NAME_add_entry_by_NID(subject, NID_commonName, MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(commonName.c_str()), -1, -1, 0) == 1);
    }

    if (ok)
    {
        ok = (X509_set_subject_name(cert, subject) == 1);
    }

    if (ok)
    {
        if (request.type == CertificateType::root)
        {
            ok = (X509_set_issuer_name(cert, subject) == 1);
        }
        else
        {
            ok = (X509_set_issuer_name(cert, X509_get_subject_name(issuerCert)) == 1);
        }
    }

    X509V3_CTX ext_ctx = {};
    if (ok)
    {
        X509V3_set_ctx(&ext_ctx, issuerCert, cert, NULL, NULL, X509V3_CTX_REPLACE);
        X509V3_set_issuer_pkey(&ext_ctx, issuerKey);
    }

    BASIC_CONSTRAINTS *bc = nullptr;
    if (ok)
    {
        bc = BASIC_CONSTRAINTS_new();
        if (bc == nullptr)
        {
            ok = false;
        }
        else
        {
            bc->ca = (request.type == CertificateType::root || request.type == CertificateType::intermediary) ? 1 : 0;
            ok = (X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT) == 1);
        }
    }

    if (bc)
    {
        BASIC_CONSTRAINTS_free(bc);
    }

    auto addConfExt = [&] (int nid, const char *value) -> bool {

        X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ext_ctx, nid, const_cast<char *>(value));
        if (ex == nullptr)
        {
            return false;
        }

        bool added = (X509_add_ext(cert, ex, -1) == 1);
        X509_EXTENSION_free(ex);
        return added;
    };

    if (ok)
    {
        const char *keyUsages =
            (request.type == CertificateType::root || request.type == CertificateType::intermediary)
            ? "critical,digitalSignature,keyCertSign,cRLSign"
            : "critical,digitalSignature";
        ok = addConfExt(NID_key_usage, keyUsages);
    }

    if (ok && (request.enableClientAuth || request.enableServerAuth))
    {
        String usages = {};
        usages.assign("critical"_ctv);
        if (request.enableServerAuth)
        {
            usages.append(",TLS Web Server Authentication"_ctv);
        }
        if (request.enableClientAuth)
        {
            usages.append(",TLS Web Client Authentication"_ctv);
        }

        ok = addConfExt(NID_ext_key_usage, usages.c_str());
    }

    if (ok && request.subjectAltURI.size() > 0)
    {
        GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
        if (gens == nullptr)
        {
            ok = false;
        }
        else
        {
            GENERAL_NAME *gen = GENERAL_NAME_new();
            ASN1_IA5STRING *uri = ASN1_IA5STRING_new();
            String subjectAltURI = {};
            subjectAltURI.assign(request.subjectAltURI);
            if (gen == nullptr || uri == nullptr
                || ASN1_STRING_set(uri, subjectAltURI.c_str(), int(subjectAltURI.size())) != 1)
            {
                if (gen) GENERAL_NAME_free(gen);
                if (uri) ASN1_IA5STRING_free(uri);
                sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
                ok = false;
            }
            else
            {
                GENERAL_NAME_set0_value(gen, GEN_URI, uri);
                sk_GENERAL_NAME_push(gens, gen);
                ok = (X509_add1_ext_i2d(cert, NID_subject_alt_name, gens, 1, X509V3_ADD_APPEND) == 1);
                sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
            }
        }
    }

    if (ok)
    {
        ok = addConfExt(NID_subject_key_identifier, "hash");
    }

    if (ok)
    {
        ok = addConfExt(NID_authority_key_identifier, "keyid:always,issuer:always");
    }

    if (ok)
    {
        ok = (X509_sign(cert, issuerKey, (request.scheme == CryptoScheme::ed25519) ? NULL : EVP_sha256()) != 0);
    }

    if (subject)
    {
        X509_NAME_free(subject);
    }

    if (publicKey)
    {
        EVP_PKEY_free(publicKey);
    }

    if (ok == false)
    {
        if (failure) failure->assign("failed to issue certificate"_ctv);
        if (cert)
        {
            X509_free(cert);
            cert = nullptr;
        }
        if (privateKey)
        {
            EVP_PKEY_free(privateKey);
            privateKey = nullptr;
        }
        return false;
    }

    return true;
}
namespace Vault
{

static bool setRandomSerialNumber(X509 *cert)
{
    if (cert == nullptr)
    {
        return false;
    }

    uint128_t serialNumber = 0;
    Crypto::fillWithSecureRandomBytes(reinterpret_cast<uint8_t *>(&serialNumber), sizeof(serialNumber));
    BIGNUM *serial = BN_bin2bn(reinterpret_cast<const unsigned char *>(&serialNumber), sizeof(serialNumber), nullptr);
    if (serial == nullptr)
    {
        return false;
    }

    ASN1_INTEGER *asn1 = BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert));
    BN_free(serial);
    return (asn1 != nullptr);
}

static EVP_PKEY *generateEd25519Key(void)
{
    EVP_PKEY *key = nullptr;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (context == nullptr)
    {
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_keygen(context, &key) != 1)
    {
        EVP_PKEY_CTX_free(context);
        if (key)
        {
            EVP_PKEY_free(key);
        }
        return nullptr;
    }

    EVP_PKEY_CTX_free(context);
    return key;
}

static bool appendNameField(X509_NAME *name, int nid, const String& value)
{
    if (name == nullptr || value.size() == 0)
    {
        return false;
    }

    String owned = {};
    owned.assign(value);
    return X509_NAME_add_entry_by_NID(
        name,
        nid,
        MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(owned.c_str()),
        -1,
        -1,
        0) == 1;
}

static bool addExtension(X509 *cert, X509V3_CTX *context, int nid, const char *value)
{
    if (cert == nullptr || context == nullptr || value == nullptr)
    {
        return false;
    }

    X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, context, nid, const_cast<char *>(value));
    if (extension == nullptr)
    {
        return false;
    }

    bool ok = (X509_add_ext(cert, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    return ok;
}

static void appendUniqueIPLiteral(Vector<String>& addresses, const String& literal)
{
   if (literal.size() == 0)
   {
       return;
   }

    String ownedLiteral = {};
    ownedLiteral.assign(literal);
    struct in_addr ipv4 = {};
    struct in6_addr ipv6 = {};
    if (inet_pton(AF_INET, ownedLiteral.c_str(), &ipv4) != 1 && inet_pton(AF_INET6, ownedLiteral.c_str(), &ipv6) != 1)
    {
        return;
    }

    for (const String& existing : addresses)
    {
        if (existing.equals(literal))
        {
            return;
        }
    }

    addresses.push_back(literal);
}

static bool addIPSubjectAltNames(X509 *cert, X509 *issuer, const Vector<String>& addresses)
{
    if (cert == nullptr || addresses.empty())
    {
        return true;
    }

    X509V3_CTX context = {};
    X509V3_set_ctx(&context, issuer, cert, nullptr, nullptr, 0);

    String value = {};
    for (uint32_t index = 0; index < addresses.size(); ++index)
    {
        if (index > 0)
        {
            value.append(","_ctv);
        }

        value.append("IP:"_ctv);
        value.append(addresses[index]);
    }

    return addExtension(cert, &context, NID_subject_alt_name, value.c_str());
}

static bool assignOpenSSLFailure(String *failure, const char *prefix)
{
    if (failure == nullptr)
    {
        return false;
    }

    failure->assign(prefix);
    unsigned long error = ERR_peek_last_error();
    if (error != 0)
    {
        failure->append(": "_ctv);
        failure->append(ERR_error_string(error, nullptr));
    }

    return false;
}

static bool buildNodeCommonName(uint128_t uuid, String& commonName)
{
    if (uuid == 0)
    {
        return false;
    }

    char buffer[33] = {};
    std::snprintf(buffer, sizeof(buffer), "%016llx%016llx",
        (unsigned long long)(uint64_t(uuid >> 64)),
        (unsigned long long)(uint64_t(uuid)));
    commonName.assign(buffer);
    return (commonName.size() == 32);
}

static bool parseNodeCommonName(const String& encoded, uint128_t& uuid)
{
    uuid = 0;
    if (encoded.size() != 32)
    {
        return false;
    }

    char buffer[33] = {};
    memcpy(buffer, encoded.data(), 32);

    unsigned long long upper = 0;
    unsigned long long lower = 0;
    if (std::sscanf(buffer, "%16llx%16llx", &upper, &lower) != 2)
    {
        return false;
    }

    uuid = (uint128_t(upper) << 64) | uint128_t(lower);
    return (uuid != 0);
}

class TransportCertificateOptions
{
public:

    String subjectOrganization = {};
    String rootCommonName = "transport-root"_ctv;
    uint32_t rootValidityDays = 3650;
    uint32_t nodeValidityDays = 825;
};

static bool issueTransportCertificateEd25519(
    const String& commonName,
    const String& subjectOrganization,
    bool isCertificateAuthority,
    bool enableServerAuth,
    bool enableClientAuth,
    uint32_t validityDays,
    const Vector<String>& ipAddresses,
    X509 *signerCert,
    EVP_PKEY *signerKey,
    X509 *&cert,
    EVP_PKEY *&privateKey,
    String *failure = nullptr)
{
    cert = nullptr;
    privateKey = nullptr;
    if (failure)
    {
        failure->clear();
    }
    ERR_clear_error();

    privateKey = generateEd25519Key();
    cert = X509_new();
    if (privateKey == nullptr || cert == nullptr)
    {
        assignOpenSSLFailure(failure, "failed to allocate transport certificate state");
        if (cert)
        {
            X509_free(cert);
            cert = nullptr;
        }
        if (privateKey)
        {
            EVP_PKEY_free(privateKey);
            privateKey = nullptr;
        }
        return false;
    }

    X509 *issuerCert = signerCert;
    EVP_PKEY *issuerPrivateKey = signerKey;
    if (issuerCert == nullptr || issuerPrivateKey == nullptr)
    {
        issuerCert = cert;
        issuerPrivateKey = privateKey;
    }

    bool ok = (X509_set_version(cert, 2) == 1);
    if (ok)
    {
        ok = setRandomSerialNumber(cert);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate serial");
        }
    }
    if (ok)
    {
        ok = (X509_set_pubkey(cert, privateKey) == 1);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate public key");
        }
    }
    if (ok)
    {
        ok = (X509_gmtime_adj(X509_getm_notBefore(cert), 0) != nullptr);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate notBefore");
        }
    }

    uint32_t effectiveValidityDays = validityDays;
    if (effectiveValidityDays == 0)
    {
        effectiveValidityDays = isCertificateAuthority ? 3650 : 825;
    }
    if (ok)
    {
        ok = (X509_time_adj_ex(X509_getm_notAfter(cert), int(effectiveValidityDays), 0, nullptr) != nullptr);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate notAfter");
        }
    }

    X509_NAME *subject = X509_NAME_new();
    if (subject == nullptr)
    {
        ok = assignOpenSSLFailure(failure, "failed to allocate transport certificate subject");
    }
    if (ok && subjectOrganization.size() > 0)
    {
        ok = appendNameField(subject, NID_organizationName, subjectOrganization);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate organization");
        }
    }
    if (ok)
    {
        ok = appendNameField(subject, NID_commonName, commonName);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate commonName");
        }
    }
    if (ok)
    {
        ok = (X509_set_subject_name(cert, subject) == 1);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate subject");
        }
    }
    if (ok)
    {
        ok = (X509_set_issuer_name(cert, X509_get_subject_name(issuerCert)) == 1);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to set transport certificate issuer");
        }
    }

    X509V3_CTX context = {};
    if (ok)
    {
        X509V3_set_ctx(&context, issuerCert, cert, nullptr, nullptr, 0);
        X509V3_set_issuer_pkey(&context, issuerPrivateKey);
    }
    if (ok)
    {
        ok = addExtension(
            cert,
            &context,
            NID_basic_constraints,
            isCertificateAuthority ? "critical,CA:TRUE" : "critical,CA:FALSE");
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport basicConstraints");
        }
    }
    if (ok)
    {
        ok = addExtension(
            cert,
            &context,
            NID_key_usage,
            isCertificateAuthority
               ? "critical,digitalSignature,keyCertSign,cRLSign"
               : "critical,digitalSignature");
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport keyUsage");
        }
    }
    if (ok && (enableServerAuth || enableClientAuth))
    {
        String extendedKeyUsage = {};
        extendedKeyUsage.assign("critical"_ctv);
        if (enableServerAuth)
        {
            extendedKeyUsage.append(",TLS Web Server Authentication"_ctv);
        }
        if (enableClientAuth)
        {
            extendedKeyUsage.append(",TLS Web Client Authentication"_ctv);
        }

        ok = addExtension(cert, &context, NID_ext_key_usage, extendedKeyUsage.c_str());
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport extendedKeyUsage");
        }
    }
    if (ok)
    {
        ok = addExtension(cert, &context, NID_subject_key_identifier, "hash");
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport subjectKeyIdentifier");
        }
    }
    if (ok)
    {
        ok = addExtension(
            cert,
            &context,
            NID_authority_key_identifier,
            (issuerCert == cert) ? "keyid:always" : "keyid:always,issuer:always");
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport authorityKeyIdentifier");
        }
    }
    if (ok)
    {
        ok = addIPSubjectAltNames(cert, issuerCert, ipAddresses);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to add transport subjectAltName");
        }
    }
    if (ok)
    {
        ok = (X509_sign(cert, issuerPrivateKey, nullptr) != 0);
        if (ok == false)
        {
            assignOpenSSLFailure(failure, "failed to sign transport certificate");
        }
    }

    if (subject)
    {
        X509_NAME_free(subject);
    }

    if (ok == false)
    {
        if (failure && failure->size() == 0) failure->assign("failed to issue transport certificate"_ctv);
        if (cert)
        {
            X509_free(cert);
            cert = nullptr;
        }
        if (privateKey)
        {
            EVP_PKEY_free(privateKey);
            privateKey = nullptr;
        }
        return false;
    }

    if (failure)
    {
        failure->clear();
    }
    return true;
}

static bool generateTransportRootCertificateEd25519(
    String& certPem,
    String& keyPem,
    const TransportCertificateOptions& options,
    String *failure = nullptr)
{
    certPem.clear();
    keyPem.clear();

    X509 *cert = nullptr;
    EVP_PKEY *rootKey = nullptr;
    bool ok = issueTransportCertificateEd25519(
        options.rootCommonName,
        options.subjectOrganization,
        true,
        false,
        false,
        options.rootValidityDays,
        {},
        nullptr,
        nullptr,
        cert,
        rootKey,
        failure)
        && VaultPem::x509ToPem(cert, certPem)
        && VaultPem::privateKeyToPem(rootKey, keyPem);

    if (cert)
    {
        X509_free(cert);
    }
    if (rootKey)
    {
        EVP_PKEY_free(rootKey);
    }

    if (ok == false)
    {
        certPem.clear();
        keyPem.clear();
        if (failure && failure->size() == 0) failure->assign("failed to generate transport root certificate"_ctv);
        return false;
    }

    if (failure) failure->clear();
    return true;
}

static bool generateTransportRootCertificateEd25519(String& certPem, String& keyPem, String *failure = nullptr)
{
    return generateTransportRootCertificateEd25519(certPem, keyPem, TransportCertificateOptions {}, failure);
}

static bool generateTransportNodeCertificateEd25519(
    const String& rootCertPem,
    const String& rootKeyPem,
    uint128_t uuid,
    const Vector<String>& ipAddresses,
    String& certPem,
    String& keyPem,
    const TransportCertificateOptions& options,
    String *failure = nullptr)
{
    certPem.clear();
    keyPem.clear();

    X509 *rootCert = VaultPem::x509FromPem(rootCertPem);
    EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(rootKeyPem);
    if (rootCert == nullptr || rootKey == nullptr)
    {
        if (rootCert) X509_free(rootCert);
        if (rootKey) EVP_PKEY_free(rootKey);
        if (failure) failure->assign("invalid transport root material"_ctv);
        return false;
    }

    String commonName = {};
    if (buildNodeCommonName(uuid, commonName) == false)
    {
        X509_free(rootCert);
        EVP_PKEY_free(rootKey);
        if (failure) failure->assign("invalid transport node uuid"_ctv);
        return false;
    }

    X509 *cert = nullptr;
    EVP_PKEY *nodeKey = nullptr;
    bool ok = issueTransportCertificateEd25519(
        commonName,
        options.subjectOrganization,
        false,
        true,
        true,
        options.nodeValidityDays,
        ipAddresses,
        rootCert,
        rootKey,
        cert,
        nodeKey,
        failure)
        && VaultPem::x509ToPem(cert, certPem)
        && VaultPem::privateKeyToPem(nodeKey, keyPem);

    X509_free(rootCert);
    EVP_PKEY_free(rootKey);
    if (cert)
    {
        X509_free(cert);
    }
    if (nodeKey)
    {
        EVP_PKEY_free(nodeKey);
    }

    if (ok == false)
    {
        certPem.clear();
        keyPem.clear();
        if (failure && failure->size() == 0) failure->assign("failed to generate transport node certificate"_ctv);
        return false;
    }

    if (failure) failure->clear();
    return true;
}

static bool generateTransportNodeCertificateEd25519(
    const String& rootCertPem,
    const String& rootKeyPem,
    uint128_t uuid,
    const Vector<String>& ipAddresses,
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
    return generateTransportNodeCertificateEd25519(
        rootCertPem,
        rootKeyPem,
        uuid,
        ipAddresses,
        certPem,
        keyPem,
        TransportCertificateOptions {},
        failure);
}

static bool extractTransportCertificateUUID(X509 *cert, uint128_t& uuid)
{
    uuid = 0;
    if (cert == nullptr)
    {
        return false;
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject == nullptr)
    {
        return false;
    }

    char buffer[128] = {};
    int length = X509_NAME_get_text_by_NID(subject, NID_commonName, buffer, sizeof(buffer));
    if (length <= 0 || length != 32)
    {
        return false;
    }

    String encoded = {};
    encoded.assign(buffer, uint32_t(length));
    return parseNodeCommonName(encoded, uuid);
}

class SSHKeyPackage
{
public:

    String privateKeyOpenSSH = {};
    String publicKeyOpenSSH = {};

    void clear(void)
    {
        privateKeyOpenSSH.clear();
        publicKeyOpenSSH.clear();
    }
};

static bool assignSSHFailure(String *failure, const char *message)
{
    if (failure != nullptr)
    {
        failure->assign(message);
    }

    return false;
}

static void appendSSHUint32BE(String& out, uint32_t value)
{
    uint8_t bytes[4] = {
        uint8_t((value >> 24) & 0xff),
        uint8_t((value >> 16) & 0xff),
        uint8_t((value >> 8) & 0xff),
        uint8_t(value & 0xff)};
    out.append(bytes, sizeof(bytes));
}

static bool consumeSSHUint32BE(const uint8_t *&cursor, const uint8_t *end, uint32_t& value)
{
    if (uint64_t(end - cursor) < 4)
    {
        return false;
    }

    value = (uint32_t(cursor[0]) << 24) |
            (uint32_t(cursor[1]) << 16) |
            (uint32_t(cursor[2]) << 8) |
            uint32_t(cursor[3]);
    cursor += 4;
    return true;
}

static void appendSSHBinaryString(String& out, const uint8_t *data, uint32_t size)
{
    appendSSHUint32BE(out, size);
    if (size > 0)
    {
        out.append(data, size);
    }
}

static void appendSSHString(String& out, std::string_view value)
{
    appendSSHBinaryString(out, reinterpret_cast<const uint8_t *>(value.data()), uint32_t(value.size()));
}

static bool consumeSSHBinaryString(const uint8_t *&cursor, const uint8_t *end, const uint8_t *&data, uint32_t& size)
{
    if (consumeSSHUint32BE(cursor, end, size) == false)
    {
        return false;
    }

    if (uint64_t(end - cursor) < size)
    {
        return false;
    }

    data = cursor;
    cursor += size;
    return true;
}

static bool sshCommentIsAllowed(const String& comment)
{
    for (uint64_t index = 0; index < comment.size(); ++index)
    {
        uint8_t byte = comment.data()[index];
        if (byte == '\0' || byte == '\r' || byte == '\n')
        {
            return false;
        }
    }

    return true;
}

static void appendWrappedSSHBase64(String& out, const String& encoded, uint64_t width)
{
    for (uint64_t offset = 0; offset < encoded.size(); offset += width)
    {
        uint64_t chunkSize = encoded.size() - offset;
        if (chunkSize > width)
        {
            chunkSize = width;
        }

        out.append(encoded.data() + offset, chunkSize);
        out.append('\n');
    }
}

static bool parseSSHEd25519PublicBlob(const uint8_t *data,
                                      uint64_t size,
                                      std::array<uint8_t, 32>& publicKey,
                                      String *failure = nullptr)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;

    const uint8_t *keyTypeData = nullptr;
    uint32_t keyTypeSize = 0;
    if (consumeSSHBinaryString(cursor, end, keyTypeData, keyTypeSize) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 public key blob is truncated");
    }

    std::string_view keyType(reinterpret_cast<const char *>(keyTypeData), keyTypeSize);
    if (keyType != "ssh-ed25519")
    {
        return assignSSHFailure(failure, "ssh client only accepts ssh-ed25519 keypairs");
    }

    const uint8_t *publicKeyData = nullptr;
    uint32_t publicKeySize = 0;
    if (consumeSSHBinaryString(cursor, end, publicKeyData, publicKeySize) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 public key blob is truncated");
    }

    if (publicKeySize != publicKey.size())
    {
        return assignSSHFailure(failure, "ssh ed25519 public key blob has invalid key size");
    }

    if (cursor != end)
    {
        return assignSSHFailure(failure, "ssh ed25519 public key blob has trailing bytes");
    }

    std::memcpy(publicKey.data(), publicKeyData, publicKey.size());
    return true;
}

static bool parseSSHEd25519PublicKeyLine(const String& publicKeyOpenSSH,
                                         std::array<uint8_t, 32>& publicKey,
                                         String *failure = nullptr)
{
    std::string_view text(reinterpret_cast<const char *>(publicKeyOpenSSH.data()), size_t(publicKeyOpenSSH.size()));
    while (text.empty() == false &&
           (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n'))
    {
        text.remove_prefix(1);
    }

    while (text.empty() == false &&
           (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n'))
    {
        text.remove_suffix(1);
    }

    size_t algorithmEnd = text.find_first_of(" \t");
    if (algorithmEnd == std::string_view::npos || text.substr(0, algorithmEnd) != "ssh-ed25519")
    {
        return assignSSHFailure(failure, "ssh client only accepts ssh-ed25519 keypairs");
    }

    text.remove_prefix(algorithmEnd);
    while (text.empty() == false && (text.front() == ' ' || text.front() == '\t'))
    {
        text.remove_prefix(1);
    }

    if (text.empty())
    {
        return assignSSHFailure(failure, "ssh ed25519 public key is missing base64 payload");
    }

    size_t blobEnd = text.find_first_of(" \t");
    std::string_view encoded = (blobEnd == std::string_view::npos) ? text : text.substr(0, blobEnd);

    String decoded = {};
    if (Base64::decode(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size(), decoded) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 public key base64 payload is invalid");
    }

    return parseSSHEd25519PublicBlob(decoded.data(), decoded.size(), publicKey, failure);
}

static bool extractOpenSSHPrivateKeyBody(const String& privateKeyOpenSSH, String& decodedBody, String *failure = nullptr)
{
    constexpr std::string_view beginMarker = "-----BEGIN OPENSSH PRIVATE KEY-----";
    constexpr std::string_view endMarker = "-----END OPENSSH PRIVATE KEY-----";

    std::string_view text(reinterpret_cast<const char *>(privateKeyOpenSSH.data()), size_t(privateKeyOpenSSH.size()));
    while (text.empty() == false &&
           (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n'))
    {
        text.remove_prefix(1);
    }

    if (text.substr(0, beginMarker.size()) != beginMarker)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key must be an OPENSSH PRIVATE KEY block");
    }

    size_t endMarkerPosition = text.find(endMarker);
    if (endMarkerPosition == std::string_view::npos)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key footer is missing");
    }

    std::string_view body = text.substr(beginMarker.size(), endMarkerPosition - beginMarker.size());
    std::string_view suffix = text.substr(endMarkerPosition + endMarker.size());
    for (char byte : suffix)
    {
        if (byte != ' ' && byte != '\t' && byte != '\r' && byte != '\n')
        {
            return assignSSHFailure(failure, "ssh ed25519 private key has trailing non-whitespace data");
        }
    }

    String encoded = {};
    for (char byte : body)
    {
        if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n')
        {
            continue;
        }

        encoded.append(byte);
    }

    if (encoded.size() == 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key body is empty");
    }

    if (Base64::decode(encoded.data(), encoded.size(), decodedBody) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key base64 payload is invalid");
    }

    return true;
}

static bool parseSSHEd25519PrivateKey(const String& privateKeyOpenSSH,
                                      std::array<uint8_t, 32>& publicKey,
                                      String *failure = nullptr)
{
    String decodedBody = {};
    if (extractOpenSSHPrivateKeyBody(privateKeyOpenSSH, decodedBody, failure) == false)
    {
        return false;
    }

    static constexpr char openSSHMagic[] = "openssh-key-v1";
    static constexpr uint64_t openSSHMagicSize = sizeof(openSSHMagic);
    const uint8_t *cursor = decodedBody.data();
    const uint8_t *end = decodedBody.data() + decodedBody.size();
    if (uint64_t(end - cursor) < openSSHMagicSize || std::memcmp(cursor, openSSHMagic, openSSHMagicSize) != 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key magic is invalid");
    }

    cursor += openSSHMagicSize;

    const uint8_t *cipherNameData = nullptr;
    uint32_t cipherNameSize = 0;
    const uint8_t *kdfNameData = nullptr;
    uint32_t kdfNameSize = 0;
    const uint8_t *kdfOptionsData = nullptr;
    uint32_t kdfOptionsSize = 0;
    if (consumeSSHBinaryString(cursor, end, cipherNameData, cipherNameSize) == false ||
        consumeSSHBinaryString(cursor, end, kdfNameData, kdfNameSize) == false ||
        consumeSSHBinaryString(cursor, end, kdfOptionsData, kdfOptionsSize) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key header is truncated");
    }

    std::string_view cipherName(reinterpret_cast<const char *>(cipherNameData), cipherNameSize);
    std::string_view kdfName(reinterpret_cast<const char *>(kdfNameData), kdfNameSize);
    if (cipherName != "none" || kdfName != "none" || kdfOptionsSize != 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key must be unencrypted OpenSSH key material");
    }

    uint32_t numberOfKeys = 0;
    if (consumeSSHUint32BE(cursor, end, numberOfKeys) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key key-count field is missing");
    }

    if (numberOfKeys != 1)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key must contain exactly one key");
    }

    const uint8_t *publicBlobData = nullptr;
    uint32_t publicBlobSize = 0;
    const uint8_t *privateSectionData = nullptr;
    uint32_t privateSectionSize = 0;
    if (consumeSSHBinaryString(cursor, end, publicBlobData, publicBlobSize) == false ||
        consumeSSHBinaryString(cursor, end, privateSectionData, privateSectionSize) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key body is truncated");
    }

    if (cursor != end)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key has trailing bytes");
    }

    std::array<uint8_t, 32> publicKeyFromBlob = {};
    if (parseSSHEd25519PublicBlob(publicBlobData, publicBlobSize, publicKeyFromBlob, failure) == false)
    {
        return false;
    }

    const uint8_t *privateCursor = privateSectionData;
    const uint8_t *privateEnd = privateSectionData + privateSectionSize;

    uint32_t checkA = 0;
    uint32_t checkB = 0;
    if (consumeSSHUint32BE(privateCursor, privateEnd, checkA) == false ||
        consumeSSHUint32BE(privateCursor, privateEnd, checkB) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key check integers are missing");
    }

    if (checkA != checkB)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key check integers do not match");
    }

    const uint8_t *keyTypeData = nullptr;
    uint32_t keyTypeSize = 0;
    const uint8_t *publicKeyData = nullptr;
    uint32_t publicKeySize = 0;
    const uint8_t *privateKeyData = nullptr;
    uint32_t privateKeySize = 0;
    const uint8_t *commentData = nullptr;
    uint32_t commentSize = 0;
    if (consumeSSHBinaryString(privateCursor, privateEnd, keyTypeData, keyTypeSize) == false ||
        consumeSSHBinaryString(privateCursor, privateEnd, publicKeyData, publicKeySize) == false ||
        consumeSSHBinaryString(privateCursor, privateEnd, privateKeyData, privateKeySize) == false ||
        consumeSSHBinaryString(privateCursor, privateEnd, commentData, commentSize) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key body is truncated");
    }

    (void)commentData;
    (void)commentSize;

    std::string_view keyType(reinterpret_cast<const char *>(keyTypeData), keyTypeSize);
    if (keyType != "ssh-ed25519")
    {
        return assignSSHFailure(failure, "ssh client only accepts ssh-ed25519 keypairs");
    }

    if (publicKeySize != publicKey.size())
    {
        return assignSSHFailure(failure, "ssh ed25519 private key has invalid public key size");
    }

    if (privateKeySize != 64)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key has invalid private key size");
    }

    if (std::memcmp(privateKeyData + 32, publicKeyData, publicKey.size()) != 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key does not match its embedded public key");
    }

    for (uint32_t paddingIndex = 0; privateCursor < privateEnd; ++paddingIndex, ++privateCursor)
    {
        if (*privateCursor != uint8_t(paddingIndex + 1))
        {
            return assignSSHFailure(failure, "ssh ed25519 private key padding is invalid");
        }
    }

    if (std::memcmp(publicKeyFromBlob.data(), publicKeyData, publicKey.size()) != 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 private key public blobs do not match");
    }

    std::memcpy(publicKey.data(), publicKeyData, publicKey.size());
    return true;
}

static bool validateSSHKeyPackageEd25519(const String& privateKeyOpenSSH,
                                         const String& publicKeyOpenSSH,
                                         String *failure = nullptr)
{
    if (failure != nullptr)
    {
        failure->clear();
    }

    std::array<uint8_t, 32> publicKeyFromPrivate = {};
    if (parseSSHEd25519PrivateKey(privateKeyOpenSSH, publicKeyFromPrivate, failure) == false)
    {
        return false;
    }

    std::array<uint8_t, 32> publicKeyFromLine = {};
    if (parseSSHEd25519PublicKeyLine(publicKeyOpenSSH, publicKeyFromLine, failure) == false)
    {
        return false;
    }

    if (std::memcmp(publicKeyFromPrivate.data(), publicKeyFromLine.data(), publicKeyFromPrivate.size()) != 0)
    {
        return assignSSHFailure(failure, "ssh ed25519 public key does not match private key");
    }

    return true;
}

static bool validateSSHKeyPackageEd25519(const SSHKeyPackage& package, String *failure = nullptr)
{
    return validateSSHKeyPackageEd25519(package.privateKeyOpenSSH, package.publicKeyOpenSSH, failure);
}

static bool generateSSHKeyPackageEd25519(SSHKeyPackage& package,
                                         const String& comment = {},
                                         String *failure = nullptr)
{
    package.clear();
    if (failure != nullptr)
    {
        failure->clear();
    }
    ERR_clear_error();

    if (sshCommentIsAllowed(comment) == false)
    {
        return assignSSHFailure(failure, "ssh ed25519 key comment must be single-line text");
    }

    EVP_PKEY *key = generateEd25519Key();
    if (key == nullptr)
    {
        return assignOpenSSLFailure(failure, "failed to generate ssh ed25519 key");
    }

    std::array<uint8_t, 32> rawPublicKey = {};
    size_t rawPublicKeySize = rawPublicKey.size();
    if (EVP_PKEY_get_raw_public_key(key, rawPublicKey.data(), &rawPublicKeySize) != 1 ||
        rawPublicKeySize != rawPublicKey.size())
    {
        EVP_PKEY_free(key);
        return assignOpenSSLFailure(failure, "failed to extract ssh ed25519 public key");
    }

    std::array<uint8_t, 32> rawPrivateSeed = {};
    size_t rawPrivateSeedSize = rawPrivateSeed.size();
    if (EVP_PKEY_get_raw_private_key(key, rawPrivateSeed.data(), &rawPrivateSeedSize) != 1 ||
        rawPrivateSeedSize != rawPrivateSeed.size())
    {
        EVP_PKEY_free(key);
        return assignOpenSSLFailure(failure, "failed to extract ssh ed25519 private key");
    }

    EVP_PKEY_free(key);

    String publicBlob = {};
    appendSSHString(publicBlob, "ssh-ed25519");
    appendSSHBinaryString(publicBlob, rawPublicKey.data(), rawPublicKey.size());

    String encodedPublicBlob = {};
    Base64::encode(publicBlob.data(), publicBlob.size(), encodedPublicBlob);

    package.publicKeyOpenSSH.assign("ssh-ed25519 "_ctv);
    package.publicKeyOpenSSH.append(encodedPublicBlob);
    if (comment.size() > 0)
    {
        package.publicKeyOpenSSH.append(' ');
        package.publicKeyOpenSSH.append(comment);
    }
    package.publicKeyOpenSSH.append('\n');

    uint8_t combinedPrivateKey[64] = {};
    std::memcpy(combinedPrivateKey, rawPrivateSeed.data(), rawPrivateSeed.size());
    std::memcpy(combinedPrivateKey + rawPrivateSeed.size(), rawPublicKey.data(), rawPublicKey.size());

    uint32_t checkValue = Crypto::secureRandomNumber<uint32_t>();
    String privateSection = {};
    appendSSHUint32BE(privateSection, checkValue);
    appendSSHUint32BE(privateSection, checkValue);
    appendSSHString(privateSection, "ssh-ed25519");
    appendSSHBinaryString(privateSection, rawPublicKey.data(), rawPublicKey.size());
    appendSSHBinaryString(privateSection, combinedPrivateKey, sizeof(combinedPrivateKey));
    appendSSHBinaryString(privateSection, comment.data(), uint32_t(comment.size()));

    for (uint8_t paddingByte = 1; (privateSection.size() % 8) != 0; ++paddingByte)
    {
        privateSection.append(paddingByte);
    }

    String rawPrivateKey = {};
    static constexpr char openSSHMagic[] = "openssh-key-v1";
    rawPrivateKey.append(openSSHMagic, sizeof(openSSHMagic));
    appendSSHString(rawPrivateKey, "none");
    appendSSHString(rawPrivateKey, "none");
    appendSSHBinaryString(rawPrivateKey, nullptr, 0);
    appendSSHUint32BE(rawPrivateKey, 1);
    appendSSHBinaryString(rawPrivateKey, publicBlob.data(), uint32_t(publicBlob.size()));
    appendSSHBinaryString(rawPrivateKey, privateSection.data(), uint32_t(privateSection.size()));

    String encodedPrivateKey = {};
    Base64::encodePadded(rawPrivateKey.data(), rawPrivateKey.size(), encodedPrivateKey);

    package.privateKeyOpenSSH.assign("-----BEGIN OPENSSH PRIVATE KEY-----\n"_ctv);
    appendWrappedSSHBase64(package.privateKeyOpenSSH, encodedPrivateKey, 70);
    package.privateKeyOpenSSH.append("-----END OPENSSH PRIVATE KEY-----\n"_ctv);

    String validationFailure = {};
    if (validateSSHKeyPackageEd25519(package, &validationFailure) == false)
    {
        package.clear();
        if (failure != nullptr)
        {
            failure->assign("generated ssh ed25519 key package is invalid: "_ctv);
            failure->append(validationFailure);
        }
        return false;
    }

    if (failure != nullptr)
    {
        failure->clear();
    }
    return true;
}

}
