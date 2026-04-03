// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <limits>

#pragma once

class TLSBase {
protected:

  static BIO *get_rbio(void)
  {
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(rbio, -1);
    return rbio;
  }

  static BIO *get_wbio(void)
  {
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(wbio, -1);
    return wbio;
  }

  BIO *rbio = nullptr;
  BIO *wbio = nullptr;
  SSL_CTX *tlsctx = nullptr;
  bool tlsServer = false;

  uint32_t nEncryptedBytesToSend = 0;

public:

  SSL *ssl = nullptr;

  static struct ssl_ctx_st *generateCtx(const char *tls_chain, const char *tls_cert, const char *tls_key)
  {
    if (tls_chain == nullptr || tls_cert == nullptr || tls_key == nullptr ||
        tls_chain[0] == '\0' || tls_cert[0] == '\0' || tls_key[0] == '\0')
    {
      return nullptr;
    }

    struct ssl_ctx_st *context = SSL_CTX_new(TLS_method());
    if (context == nullptr)
    {
      return nullptr;
    }

    bool ok = (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) == 1);

    if (ok)
    {
      ok = (SSL_CTX_load_verify_locations(context, tls_chain, NULL) == 1);
    }

    if (ok)
    {
      ok = (SSL_CTX_use_certificate_file(context, tls_cert, SSL_FILETYPE_PEM) == 1);
    }

    if (ok)
    {
      ok = (SSL_CTX_use_PrivateKey_file(context, tls_key, SSL_FILETYPE_PEM) == 1);
    }

    if (ok)
    {
      ok = (SSL_CTX_check_private_key(context) == 1);
    }

    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (ok)
    {
      ok = (SSL_CTX_set_ciphersuites(context, "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256") == 1);
    }

    // boringssl
    // static const int X25519Only = NID_X25519;
    // SSL_CTX_set1_curves(context, &X25519Only, 1);
    // static const uint16_t ED25519Only = SSL_SIGN_ED25519;
    // SSL_CTX_set_signing_algorithm_prefs(context, &ED25519Only, 1);
    // SSL_CTX_set_verify_algorithm_prefs(context, &ED25519Only, 1);

    // SSL_CTX_set1_curves_list(context, "X25519");
    // SSL_CTX_set1_groups_list(context, "X25519");
    // SSL_CTX_set1_sigalgs_list(context, "ed25519");

    if (ok == false)
    {
      SSL_CTX_free(context);
      return nullptr;
    }

    return context;
  }

  static struct ssl_ctx_st *generateCtxFromPEM(
      const char *chainPem,
      uint32_t chainBytes,
      const char *certPem,
      uint32_t certBytes,
      const char *keyPem,
      uint32_t keyBytes)
  {
    if (chainPem == nullptr || certPem == nullptr || keyPem == nullptr ||
        chainBytes == 0 || certBytes == 0 || keyBytes == 0)
    {
      return nullptr;
    }

    if (chainBytes > static_cast<uint32_t>(std::numeric_limits<int>::max()) ||
        certBytes > static_cast<uint32_t>(std::numeric_limits<int>::max()) ||
        keyBytes > static_cast<uint32_t>(std::numeric_limits<int>::max()))
    {
      return nullptr;
    }

    struct ssl_ctx_st *context = SSL_CTX_new(TLS_method());
    if (context == nullptr)
    {
      return nullptr;
    }

    bool ok = (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) == 1);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (ok)
    {
      ok = (SSL_CTX_set_ciphersuites(context, "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256") == 1);
    }

    bool loadedChain = false;
    BIO *chainStoreBio = BIO_new_mem_buf(chainPem, int(chainBytes));
    if (chainStoreBio)
    {
      X509_STORE *store = SSL_CTX_get_cert_store(context);
      if (store)
      {
        while (true)
        {
          X509 *ca = PEM_read_bio_X509(chainStoreBio, nullptr, nullptr, nullptr);
          if (ca == nullptr)
          {
            break;
          }

          loadedChain = true;
          if (X509_STORE_add_cert(store, ca) != 1)
          {
            ERR_clear_error();
          }

          X509_free(ca);
        }
      }

      BIO_free(chainStoreBio);
    }

    BIO *certBio = BIO_new_mem_buf(certPem, int(certBytes));
    BIO *keyBio = BIO_new_mem_buf(keyPem, int(keyBytes));

    ok = ok && (certBio != nullptr && keyBio != nullptr && loadedChain);
    X509 *cert = nullptr;
    EVP_PKEY *key = nullptr;

    if (ok)
    {
      cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
      key = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
      ok = (cert != nullptr && key != nullptr);
    }

    if (ok)
    {
      ok = (SSL_CTX_use_certificate(context, cert) == 1);
    }

    if (ok)
    {
      ok = (SSL_CTX_use_PrivateKey(context, key) == 1);
    }

    if (ok)
    {
      ok = (SSL_CTX_check_private_key(context) == 1);
    }

    if (ok)
    {
      BIO *chainPresentBio = BIO_new_mem_buf(chainPem, int(chainBytes));
      if (chainPresentBio == nullptr)
      {
        ok = false;
      }
      else
      {
        while (true)
        {
          X509 *chainCert = PEM_read_bio_X509(chainPresentBio, nullptr, nullptr, nullptr);
          if (chainCert == nullptr)
          {
            break;
          }

          if (SSL_CTX_add_extra_chain_cert(context, chainCert) != 1)
          {
            X509_free(chainCert);
            ERR_clear_error();
            ok = false;
            break;
          }
        }

        BIO_free(chainPresentBio);
      }
    }

    if (cert)
    {
      X509_free(cert);
    }

    if (key)
    {
      EVP_PKEY_free(key);
    }

    if (certBio)
    {
      BIO_free(certBio);
    }

    if (keyBio)
    {
      BIO_free(keyBio);
    }

    if (ok == false)
    {
      SSL_CTX_free(context);
      return nullptr;
    }

    return context;
  }

  static bool configureBasicsCtxFromPEM(
      const char *chainPem,
      uint32_t chainBytes,
      const char *certPem,
      uint32_t certBytes,
      const char *keyPem,
      uint32_t keyBytes)
  {
    struct ssl_ctx_st *ctx = generateCtxFromPEM(chainPem, chainBytes, certPem, certBytes, keyPem, keyBytes);
    if (ctx == nullptr)
    {
      return false;
    }

    if (basicsCtx)
    {
      SSL_CTX_free(basicsCtx);
    }

    basicsCtx = ctx;
    return true;
  }

  static inline struct ssl_ctx_st *basicsCtx = nullptr;

  bool isTLSNegotiated(void) const
  {
    return (ssl != nullptr && SSL_is_init_finished(ssl) == true);
  }

  uint32_t encryptedBytesToSend(void) const
  {
    return nEncryptedBytesToSend;
  }

  void noteEncryptedBytesSent(uint32_t bytes)
  {
    if (bytes >= nEncryptedBytesToSend)
    {
      nEncryptedBytesToSend = 0;
    }
    else
    {
      nEncryptedBytesToSend -= bytes;
    }
  }

  X509 *duplicatePeerCertificate(void) const
  {
    if (ssl == nullptr)
    {
      return nullptr;
    }

    X509 *peer = SSL_get1_peer_certificate(ssl);
    return peer;
  }

  // this will only be called if pendingSend == false, or a send completes... thus all the outstanding bytes are available
  bool encryptInto(Buffer& wBuffer)
  {
    if (ssl == nullptr || rbio == nullptr || wbio == nullptr)
    {
      return false;
    }

    if (isTLSNegotiated() == false)
    {
      int handshake = SSL_do_handshake(ssl);
      if (handshake != 1)
      {
        switch (SSL_get_error(ssl, handshake))
        {
          case SSL_ERROR_WANT_READ:
          case SSL_ERROR_WANT_WRITE:
            {
              break;
            }
          case SSL_ERROR_SYSCALL:
          case SSL_ERROR_SSL:
          case SSL_ERROR_ZERO_RETURN:
          default:
            {
              wBuffer.reset();
              return false;
            }
        }
      }
    }

    if (isTLSNegotiated() && wBuffer.outstandingBytes() > 0)
    {
      const uint32_t plaintextBytes = wBuffer.outstandingBytes();
      uint32_t bytesConsumed = 0;

      do
      {
        // load all the unencrypted outgoing bytes into the ssl object
        int consumed = SSL_write(ssl, wBuffer.pHead() + bytesConsumed, plaintextBytes - bytesConsumed);

        if (consumed > 0)
        {
          bytesConsumed += consumed;
        }
        else
        {
          switch (SSL_get_error(ssl, consumed))
          {
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
              {
                wBuffer.reset();
                return false;
              }
            default:
              {
                break;
              }
          }

          break;
        }

      } while (bytesConsumed < plaintextBytes);

      if (bytesConsumed != plaintextBytes)
      {
        wBuffer.reset();
        return false;
      }

      wBuffer.zeroOut();
    }

    if (BIO_ctrl_pending(rbio) > 0)
    {
      do
      {
        // read all the encrypted bytes from the rbio into the wBuffer
        int written = BIO_read(rbio, wBuffer.pTail(), wBuffer.remainingCapacity());

        if (written > 0)
        {
          wBuffer.advance(written);
          if (wBuffer.remainingCapacity() == 0)
          {
            wBuffer.growCapacityByExponentialDecay();
          }
        }
        else
        {
          if (BIO_should_retry(rbio) == false) // error
          {
            wBuffer.reset();
            return false;
          }

          break;
        }

      } while (BIO_ctrl_pending(rbio) > 0);
    }

    nEncryptedBytesToSend = wBuffer.size();

    return true;
  }

  bool decryptFrom(Buffer& rBuffer, uint32_t bytesRecved)
  {
    if (bytesRecved == 0)
    {
      return true;
    }

    if (ssl == nullptr || rbio == nullptr || wbio == nullptr)
    {
      return false;
    }

    uint64_t originalSize = rBuffer.size();
    uint32_t bytesConsumed = 0;

    // rBuffer already has at least bytesRecved remaining capacity
    do
    {
      // there might be data in the rBuffer, so write from the tail, and don't advance
      int consumed = BIO_write(wbio, rBuffer.pTail() + bytesConsumed, bytesRecved - bytesConsumed);

      if (consumed > 0)
      {
        bytesConsumed += consumed;
      }
      else
      {
        if (BIO_should_retry(wbio) == false) // error
        {
          rBuffer.resize(originalSize);
          return false;
        }

        return true;
      }

    } while (bytesConsumed < bytesRecved);

    if (BIO_ctrl_pending(wbio) > 0 || SSL_has_pending(ssl))
    {
      do
      {
        int bytesRead = SSL_read(ssl, rBuffer.pTail(), rBuffer.remainingCapacity());

        if (bytesRead > 0)
        {
          rBuffer.advance(bytesRead);
          if (rBuffer.remainingCapacity() == 0)
          {
            rBuffer.growCapacityByExponentialDecay();
          }
        }
        else
        {
          switch (SSL_get_error(ssl, bytesRead))
          {
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
              {
                rBuffer.resize(originalSize);
                return false;
              }
            default:
              break;
          }

          break;
        }

      } while (BIO_ctrl_pending(wbio) > 0 || SSL_has_pending(ssl));
    }

    return true;
  }

  void resetTLS(void)
  {
    SSL_CTX *context = tlsctx;
    bool isServer = tlsServer;
    destroyTLS();

    if (context != nullptr)
    {
      setupTLS(context, isServer);
    }
  }

  void destroyTLS(void)
  {
    nEncryptedBytesToSend = 0;
    if (ssl)
    {
      SSL_free(ssl);
      ssl = nullptr;
    }

    rbio = nullptr;
    wbio = nullptr;
    tlsctx = nullptr;
  }

  void setupTLS(SSL_CTX *ctx, bool isServer)
  {
    destroyTLS();

    if (ctx == nullptr)
    {
      return;
    }

    rbio = get_rbio();
    wbio = get_wbio();
    tlsctx = ctx;
    tlsServer = isServer;

    ssl = SSL_new(ctx);
    if (ssl == nullptr)
    {
      BIO_free(rbio);
      BIO_free(wbio);
      rbio = nullptr;
      wbio = nullptr;
      tlsctx = nullptr;
      return;
    }

    SSL_set_bio(ssl, wbio, rbio);

    if (isServer)
    {
      SSL_set_accept_state(ssl);
    }
    else
    {
      SSL_set_connect_state(ssl);
    }
  }

  TLSBase() = default;

  virtual ~TLSBase()
  {
    destroyTLS();
  }

  TLSBase(SSL_CTX *ctx, bool isServer)
  {
    setupTLS(ctx, isServer);
  }
};
