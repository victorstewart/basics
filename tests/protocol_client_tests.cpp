// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "macros/bytes.h"
#include "services/filesystem.h"
#include "services/time.h"
#include "services/numbers.h"
#include "services/crypto.h"
#include "services/vault.h"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/pool.h"
#include "networking/coroutinestack.h"
#include "networking/stream.h"
#include "networking/tls.h"
#include "networking/ring.h"
#include "networking/reconnector.h"
#include "networking/multi.curl.client.h"
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#endif
#define private public
#include "networking/h2nb.client.h"
#undef private
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#include "networking/ssh.h"

namespace {

class TempDirectory {
private:

  std::array<char, 72> path_ {};
  bool valid_ = false;

public:

  TempDirectory()
  {
    std::snprintf(path_.data(), path_.size(), "/tmp/basics-protocol-XXXXXX");
    valid_ = (mkdtemp(path_.data()) != nullptr);
  }

  ~TempDirectory()
  {
    if (valid_)
    {
      Filesystem::eraseDirectory(String(path_.data()));
    }
  }

  bool valid() const
  {
    return valid_;
  }

  const char *path() const
  {
    return path_.data();
  }
};

static std::string joinPath(const char *root, std::string_view child)
{
  std::string path(root);
  path.push_back('/');
  path.append(child);
  return path;
}

static bool writeFile(std::string_view path, std::string_view contents)
{
  std::ofstream output(std::string(path), std::ios::binary);
  if (!output.is_open())
  {
    return false;
  }

  output.write(contents.data(), std::streamsize(contents.size()));
  return output.good();
}

static bool writeFile(StringType auto&& path, const String& contents, mode_t mode = 0600)
{
  String pathText = {};
  pathText.assign(path);

  if (writeFile(std::string_view(reinterpret_cast<const char *>(pathText.data()), size_t(pathText.size())),
                std::string_view(reinterpret_cast<const char *>(contents.data()), size_t(contents.size()))) == false)
  {
    return false;
  }

  return (chmod(pathText.c_str(), mode) == 0);
}

static std::string readFile(std::string_view path)
{
  std::ifstream input(std::string(path), std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

static int runCommand(const std::vector<std::string>& args)
{
  if (args.empty())
  {
    return -1;
  }

  std::vector<char *> argv;
  argv.reserve(args.size() + 1);
  for (const std::string& arg : args)
  {
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr);

  pid_t child = fork();
  if (child == 0)
  {
    execvp(argv[0], argv.data());
    _exit(127);
  }

  if (child < 0)
  {
    return -1;
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0)
  {
    return -1;
  }

  if (WIFEXITED(status))
  {
    return WEXITSTATUS(status);
  }

  return -1;
}

class RuntimeTLSMaterial {
private:

  TempDirectory temp_;
  std::string certPath_;
  std::string keyPath_;
  bool ready_ = false;

  // BASICS_MULTI_CURL_CERT_NATIVE_BEGIN
  static bool expireCertificate(String& certificatePath,
                                String& keyPath)
  {
    FILE *certificateFile = std::fopen(certificatePath.c_str(), "rb");
    X509 *certificate = certificateFile
                            ? PEM_read_X509(certificateFile, nullptr, nullptr, nullptr)
                            : nullptr;
    if (certificateFile)
    {
      std::fclose(certificateFile);
    }

    FILE *keyFile = std::fopen(keyPath.c_str(), "rb");
    EVP_PKEY *key = keyFile
                        ? PEM_read_PrivateKey(keyFile, nullptr, nullptr, nullptr)
                        : nullptr;
    if (keyFile)
    {
      std::fclose(keyFile);
    }

    bool ok = certificate && key &&
              ASN1_TIME_set_string(X509_getm_notBefore(certificate), "20000101000000Z") == 1 &&
              ASN1_TIME_set_string(X509_getm_notAfter(certificate), "20000102000000Z") == 1 &&
              X509_sign(certificate, key, EVP_sha256()) > 0;
    certificateFile = ok ? std::fopen(certificatePath.c_str(), "wb") : nullptr;
    ok = certificateFile && PEM_write_X509(certificateFile, certificate) == 1;
    if (certificateFile)
    {
      std::fclose(certificateFile);
    }
    EVP_PKEY_free(key);
    X509_free(certificate);
    return ok;
  }
  // BASICS_MULTI_CURL_CERT_NATIVE_END

public:

  explicit RuntimeTLSMaterial(bool expired = false)
  {
    if (!temp_.valid())
    {
      return;
    }

    certPath_ = joinPath(temp_.path(), "loopback.cert.pem");
    keyPath_ = joinPath(temp_.path(), "loopback.key.pem");

    ready_ = (runCommand({
                  "openssl",
                  "req",
                  "-x509",
                  "-nodes",
                  "-newkey",
                  "rsa:2048",
                  "-sha256",
                  "-days",
                  "1",
                  "-subj",
                  "/CN=localhost",
                  "-addext",
                  "subjectAltName=DNS:localhost,IP:127.0.0.1",
                  "-addext",
                  "basicConstraints=critical,CA:TRUE",
                  "-addext",
                  "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                  "-keyout",
                  keyPath_,
                  "-out",
                  certPath_}) == 0);
    if (ready_ && expired)
    {
      String certificatePath;
      certificatePath.assign(certPath_.data(), certPath_.size());
      String keyPath;
      keyPath.assign(keyPath_.data(), keyPath_.size());
      ready_ = expireCertificate(certificatePath, keyPath);
    }
  }

  bool ready() const
  {
    return ready_;
  }

  const std::string& certPath() const
  {
    return certPath_;
  }

  const std::string& keyPath() const
  {
    return keyPath_;
  }
};

static std::string drainOpenSSLErrors()
{
  std::string errors;
  unsigned long error = 0;
  char buffer[256] = {};

  while ((error = ERR_get_error()) != 0)
  {
    ERR_error_string_n(error, buffer, sizeof(buffer));
    if (!errors.empty())
    {
      errors.append(" | ");
    }
    errors.append(buffer);
  }

  return errors;
}

static int selectHTTP2Protocol(SSL *ssl,
                               const unsigned char **out,
                               unsigned char *outlen,
                               const unsigned char *in,
                               unsigned int inlen,
                               void *arg)
{
  (void)ssl;
  (void)arg;

  int result = nghttp2_select_alpn(out, outlen, in, inlen);
  if (result == -1)
  {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *createServerContext(const RuntimeTLSMaterial& tls, bool enableHTTP2)
{
  SSL_CTX *context = SSL_CTX_new(TLS_method());
  if (context == nullptr)
  {
    return nullptr;
  }

  bool ok = (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) == 1);
  if (ok)
  {
    ok = (SSL_CTX_set_ciphersuites(context, "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256") == 1);
  }
  if (ok)
  {
    ok = (SSL_CTX_use_certificate_file(context, tls.certPath().c_str(), SSL_FILETYPE_PEM) == 1);
  }
  if (ok)
  {
    ok = (SSL_CTX_use_PrivateKey_file(context, tls.keyPath().c_str(), SSL_FILETYPE_PEM) == 1);
  }
  if (ok)
  {
    ok = (SSL_CTX_check_private_key(context) == 1);
  }

  SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);

  if (ok && enableHTTP2)
  {
    SSL_CTX_set_alpn_select_cb(context, selectHTTP2Protocol, nullptr);
  }

  if (!ok)
  {
    SSL_CTX_free(context);
    return nullptr;
  }

  return context;
}

static void setSocketTimeouts(int fd, int seconds)
{
  timeval timeout = {.tv_sec = seconds, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int createLoopbackListener(uint16_t& port)
{
  port = 0;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }

  int reuseAddress = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseAddress, sizeof(reuseAddress));

  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;

  if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
  {
    close(fd);
    return -1;
  }

  if (listen(fd, 8) != 0)
  {
    close(fd);
    return -1;
  }

  socklen_t length = sizeof(address);
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) != 0)
  {
    close(fd);
    return -1;
  }

  port = ntohs(address.sin_port);
  return fd;
}

static bool sslWriteAll(SSL *ssl, std::string_view data)
{
  size_t offset = 0;
  while (offset < data.size())
  {
    int written = SSL_write(ssl, data.data() + offset, int(data.size() - offset));
    if (written <= 0)
    {
      return false;
    }

    offset += size_t(written);
  }

  return true;
}

static bool sslReadLine(SSL *ssl, std::string& line)
{
  line.clear();

  while (true)
  {
    char byte = 0;
    int readBytes = SSL_read(ssl, &byte, 1);
    if (readBytes <= 0)
    {
      return false;
    }

    line.push_back(byte);
    if (line.size() >= 2 && line[line.size() - 2] == '\r' && line.back() == '\n')
    {
      return true;
    }
  }
}

static bool sslReadUntil(SSL *ssl, std::string_view terminator, std::string& data)
{
  data.clear();
  std::array<char, 2048> buffer = {};

  while (true)
  {
    int readBytes = SSL_read(ssl, buffer.data(), int(buffer.size()));
    if (readBytes <= 0)
    {
      return false;
    }

    data.append(buffer.data(), size_t(readBytes));
    if (data.find(terminator) != std::string::npos)
    {
      return true;
    }
  }
}

static bool sslReadUntilNative(SSL *ssl, const char *terminator, String& data)
{
  std::string fixtureData;
  if (!sslReadUntil(ssl, terminator, fixtureData))
  {
    return false;
  }
  data.assign(fixtureData.data(), fixtureData.size());
  return true;
}

static bool sslWriteAllNative(SSL *ssl, const String& data)
{
  return sslWriteAll(ssl,
                     std::string_view(reinterpret_cast<const char *>(data.data()),
                                      size_t(data.size())));
}

class TLSLoopbackServer {
private:

  SSL_CTX *context_ = nullptr;
  int listenerFd_ = -1;
  uint16_t port_ = 0;
  std::thread thread_;

protected:

  std::string failure_;

  virtual void handleClient(SSL *ssl) = 0;

  void setFailure(const std::string& message)
  {
    if (failure_.empty())
    {
      failure_ = message;
    }
  }

public:

  TLSLoopbackServer(const RuntimeTLSMaterial& tls, bool enableHTTP2)
  {
    context_ = createServerContext(tls, enableHTTP2);
    if (context_ == nullptr)
    {
      setFailure("failed to create TLS server context: " + drainOpenSSLErrors());
      return;
    }

    listenerFd_ = createLoopbackListener(port_);
    if (listenerFd_ < 0)
    {
      setFailure("failed to create loopback listener");
      SSL_CTX_free(context_);
      context_ = nullptr;
      return;
    }

    thread_ = std::thread([this]() {
      pollfd listenerPoll = {.fd = listenerFd_, .events = POLLIN, .revents = 0};
      int pollResult = poll(&listenerPoll, 1, 3000);
      if (pollResult <= 0)
      {
        setFailure("timed out waiting for loopback client");
        return;
      }

      int clientFd = accept(listenerFd_, nullptr, nullptr);
      if (clientFd < 0)
      {
        setFailure("failed to accept loopback client");
        return;
      }

      setSocketTimeouts(clientFd, 3);

      SSL *ssl = SSL_new(context_);
      if (ssl == nullptr)
      {
        setFailure("failed to create TLS session: " + drainOpenSSLErrors());
        close(clientFd);
        return;
      }

      SSL_set_fd(ssl, clientFd);
      if (SSL_accept(ssl) != 1)
      {
        setFailure("TLS accept failed: " + drainOpenSSLErrors());
      }
      else
      {
        handleClient(ssl);
      }

      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(clientFd);
    });
  }

  virtual ~TLSLoopbackServer()
  {
    if (listenerFd_ >= 0)
    {
      close(listenerFd_);
      listenerFd_ = -1;
    }

    wait();

    if (context_ != nullptr)
    {
      SSL_CTX_free(context_);
      context_ = nullptr;
    }
  }

  bool ready() const
  {
    return context_ != nullptr && listenerFd_ >= 0 && port_ != 0;
  }

  uint16_t port() const
  {
    return port_;
  }

  const std::string& failure() const
  {
    return failure_;
  }

  void wait()
  {
    if (thread_.joinable())
    {
      thread_.join();
    }
  }
};

struct HTTP2ResponseSpec {
  int status = 200;
  std::string contentType = "application/json";
  std::string body;
  bool closeWithoutResponse = false;
};

class HTTP2Server : public TLSLoopbackServer {
public:

  struct ObservedRequest {
    std::string method;
    std::string path;
    std::string body;
  };

  using Handler = std::function<HTTP2ResponseSpec(const ObservedRequest&)>;

private:

  struct StreamState {
    std::string method;
    std::string path;
    std::string body;
  };

  struct ResponseState {
    std::string status;
    std::string contentType;
    std::string contentLength;
    std::string body;
    size_t offset = 0;
    std::array<nghttp2_nv, 3> headers = {};
  };

  Handler handler_;
  ObservedRequest lastRequest_;
  bool sawRequest_ = false;
  bool selectedHTTP2_ = false;
  bytell_hash_map<int32_t, StreamState> streams_;
  bytell_hash_map<int32_t, std::unique_ptr<ResponseState>> responses_;
  bool closeAfterRequest_ = false;

  static nghttp2_nv makeHeader(const std::string& name, const std::string& value)
  {
    return {
        reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())),
        reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
        name.size(),
        value.size(),
        NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE};
  }

  static nghttp2_nv makeHeader(const char *name, const std::string& value)
  {
    return {
        reinterpret_cast<uint8_t *>(const_cast<char *>(name)),
        reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
        std::strlen(name),
        value.size(),
        NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE};
  }

  static int onHeader(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name,
                      size_t namelen,
                      const uint8_t *value,
                      size_t valuelen,
                      uint8_t flags,
                      void *userData)
  {
    (void)session;
    (void)flags;

    if (frame->hd.stream_id <= 0 || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
      return 0;
    }

    HTTP2Server *server = static_cast<HTTP2Server *>(userData);
    StreamState& state = server->streams_[frame->hd.stream_id];
    std::string_view headerName(reinterpret_cast<const char *>(name), namelen);
    std::string_view headerValue(reinterpret_cast<const char *>(value), valuelen);

    if (headerName == ":method")
    {
      state.method.assign(headerValue);
    }
    else if (headerName == ":path")
    {
      state.path.assign(headerValue);
    }

    return 0;
  }

  static int onDataChunk(nghttp2_session *session,
                         uint8_t flags,
                         int32_t streamId,
                         const uint8_t *data,
                         size_t len,
                         void *userData)
  {
    (void)session;
    (void)flags;

    HTTP2Server *server = static_cast<HTTP2Server *>(userData);
    StreamState& state = server->streams_[streamId];
    state.body.append(reinterpret_cast<const char *>(data), len);
    return 0;
  }

  static ssize_t readResponseBody(nghttp2_session *session,
                                  int32_t streamId,
                                  uint8_t *buffer,
                                  size_t length,
                                  uint32_t *dataFlags,
                                  nghttp2_data_source *source,
                                  void *userData)
  {
    (void)session;
    (void)streamId;
    (void)userData;

    ResponseState *response = static_cast<ResponseState *>(source->ptr);
    size_t remaining = response->body.size() - response->offset;
    size_t chunk = std::min(length, remaining);

    if (chunk > 0)
    {
      std::memcpy(buffer, response->body.data() + response->offset, chunk);
      response->offset += chunk;
    }

    if (response->offset == response->body.size())
    {
      *dataFlags = NGHTTP2_DATA_FLAG_EOF;
    }

    return ssize_t(chunk);
  }

  static int onFrameRecv(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *userData)
  {
    HTTP2Server *server = static_cast<HTTP2Server *>(userData);
    if (frame->hd.stream_id <= 0)
    {
      return 0;
    }

    const bool requestEnded =
        ((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
         frame->hd.type == NGHTTP2_DATA) &&
        ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0);

    if (!requestEnded)
    {
      return 0;
    }

    auto stateIt = server->streams_.find(frame->hd.stream_id);
    if (stateIt == server->streams_.end())
    {
      return 0;
    }

    server->sawRequest_ = true;
    server->lastRequest_.method = stateIt->second.method;
    server->lastRequest_.path = stateIt->second.path;
    server->lastRequest_.body = stateIt->second.body;

    HTTP2ResponseSpec responseSpec = server->handler_(server->lastRequest_);
    if (responseSpec.closeWithoutResponse)
    {
      server->closeAfterRequest_ = true;
      return 0;
    }

    auto response = std::make_unique<ResponseState>();
    response->status = std::to_string(responseSpec.status);
    response->contentType = responseSpec.contentType;
    response->body = responseSpec.body;
    response->contentLength = std::to_string(response->body.size());
    response->headers[0] = makeHeader(":status", response->status);
    response->headers[1] = makeHeader("content-type", response->contentType);
    response->headers[2] = makeHeader("content-length", response->contentLength);

    nghttp2_data_provider provider = {};
    provider.source.ptr = response.get();
    provider.read_callback = readResponseBody;

    int submitResult = nghttp2_submit_response(
        session,
        frame->hd.stream_id,
        response->headers.data(),
        response->headers.size(),
        &provider);
    if (submitResult != 0)
    {
      server->setFailure("failed to submit http2 response");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    server->responses_[frame->hd.stream_id] = std::move(response);
    return 0;
  }

  static int onStreamClose(nghttp2_session *session,
                           int32_t streamId,
                           uint32_t errorCode,
                           void *userData)
  {
    (void)session;
    (void)errorCode;

    HTTP2Server *server = static_cast<HTTP2Server *>(userData);
    server->responses_.erase(streamId);
    server->streams_.erase(streamId);
    return 0;
  }

  bool flushPending(nghttp2_session *session, SSL *ssl)
  {
    while (nghttp2_session_want_write(session) == 1)
    {
      const uint8_t *data = nullptr;
      ssize_t written = nghttp2_session_mem_send(session, &data);
      if (written < 0)
      {
        setFailure("failed to serialize http2 frame");
        return false;
      }

      if (written == 0)
      {
        break;
      }

      if (!sslWriteAll(ssl, std::string_view(reinterpret_cast<const char *>(data), size_t(written))))
      {
        setFailure("failed to write http2 frame to tls socket");
        return false;
      }
    }

    return true;
  }

protected:

  void handleClient(SSL *ssl) override
  {
    const unsigned char *alpn = nullptr;
    unsigned int alpnLen = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpnLen);
    selectedHTTP2_ = (alpnLen == 2 && std::memcmp(alpn, "h2", 2) == 0);
    if (!selectedHTTP2_)
    {
      setFailure("http2 ALPN was not negotiated");
      return;
    }

    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session *session = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, onHeader);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, onDataChunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, onFrameRecv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, onStreamClose);

    if (nghttp2_session_server_new(&session, callbacks, this) != 0)
    {
      nghttp2_session_callbacks_del(callbacks);
      setFailure("failed to create http2 server session");
      return;
    }

    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    if (!flushPending(session, ssl))
    {
      nghttp2_session_del(session);
      nghttp2_session_callbacks_del(callbacks);
      return;
    }

    std::array<uint8_t, 16 * 1024> buffer = {};
    while (true)
    {
      int readBytes = SSL_read(ssl, buffer.data(), int(buffer.size()));
      if (readBytes <= 0)
      {
        break;
      }

      ssize_t recvResult = nghttp2_session_mem_recv(session, buffer.data(), size_t(readBytes));
      if (recvResult < 0)
      {
        setFailure("failed to parse http2 request");
        break;
      }

      if (!flushPending(session, ssl))
      {
        break;
      }

      if (closeAfterRequest_)
      {
        break;
      }
    }

    responses_.clear();
    streams_.clear();
    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
  }

public:

  HTTP2Server(const RuntimeTLSMaterial& tls, Handler handler)
      : TLSLoopbackServer(tls, true),
        handler_(std::move(handler))
  {}

  bool sawRequest() const
  {
    return sawRequest_;
  }

  bool selectedHTTP2() const
  {
    return selectedHTTP2_;
  }

  const ObservedRequest& lastRequest() const
  {
    return lastRequest_;
  }
};

class WakeTrackingCoroutineStack : public CoroutineStack {
public:

  bool woke = false;

  void co_consume() override
  {
    woke = true;
    CoroutineStack::co_consume();
  }
};

class TestH2NonBlockingClient : public H2NonBlockingClient {
public:

  enum class Mode {
    success,
    failAfterRequest,
  };

  Mode mode;
  String requestPath;
  WakeTrackingCoroutineStack wakeTracker;
  Ticket ticket;
  bool requestQueued = false;
  bool responseComplete = false;
  bool failureWakeSeen = false;

  explicit TestH2NonBlockingClient(Mode testMode, String path)
      : mode(testMode),
        requestPath(std::move(path)),
        ticket(testMode == Mode::failAfterRequest ? &wakeTracker : nullptr)
  {}

  void configure(uint16_t port)
  {
    createAndConfigureTCPSocket(AF_INET, false, 0);
    setDaddr("127.0.0.1"_ctv, port);

    std::string authorityText = "127.0.0.1:" + std::to_string(port);
    authority.assign(authorityText.c_str());
    finishSetup("127.0.0.1");

    if (mode == Mode::failAfterRequest)
    {
      ticket.wakeOnFailure = true;
    }
  }

  void connected() override
  {
    if (requestQueued)
    {
      return;
    }

    queueGet(requestPath, &ticket, CleanUpHandler {});
    requestQueued = true;
  }

  void recvHandler(void *socket, int result) override
  {
    H2NonBlockingClient::recvHandler(socket, result);

    if (mode == Mode::success &&
        ticket.count == 0 &&
        ticket.responses.size() == 1 &&
        responseComplete == false)
    {
      responseComplete = true;
      Ring::queueClose(this);
    }
  }

  void closeHandler(void *socket) override
  {
    if (mode == Mode::success && responseComplete)
    {
      Ring::exit = true;
      return;
    }

    if (mode == Mode::failAfterRequest)
    {
      failureWakeSeen = wakeTracker.woke;
      Ring::exit = true;
      return;
    }

    H2NonBlockingClient::closeHandler(socket);
  }
};

class BlockingSSHClient : public SSHClient {
protected:

  void waitForSSHIO(int64_t deadlineMs, uint64_t timeoutMs) override
  {
    (void)deadlineMs;

    if (session == nullptr || fd < 0)
    {
      failed = true;
      lastFailure.assign("ssh session unavailable while waiting for io"_ctv);
      co_return;
    }

    int directions = libssh2_session_block_directions(session);
    short events = POLLERR | POLLHUP;
    if (directions == 0 || (directions & LIBSSH2_SESSION_BLOCK_INBOUND))
    {
      events |= POLLIN;
    }
    if (directions == 0 || (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND))
    {
      events |= POLLOUT;
    }

    pollfd pfd = {.fd = fd, .events = events, .revents = 0};
    int waitMs = -1;
    if (timeoutMs > 0)
    {
      waitMs = (timeoutMs > uint64_t(std::numeric_limits<int>::max()))
                   ? std::numeric_limits<int>::max()
                   : int(timeoutMs);
    }

    int pollResult = poll(&pfd, 1, waitMs);
    if (pollResult == 0)
    {
      failed = true;
      lastFailure.assign("ssh io timed out"_ctv);
    }
    else if (pollResult < 0)
    {
      failed = true;
      lastFailure.assign("ssh io poll failed"_ctv);
    }
  }
};

static bool ensureTailCapacity(Buffer& buffer, uint64_t moreBytes);
static bool pumpTLS(TLSBase& sender, Buffer& senderBuffer, TLSBase& receiver, Buffer& receiverBuffer, bool& madeProgress);
static bool negotiateTLS(TLSBase& client,
                         Buffer& clientWire,
                         Buffer& clientPlain,
                         TLSBase& server,
                         Buffer& serverWire,
                         Buffer& serverPlain,
                         int rounds);

class InMemoryHTTP2Server {
public:

  struct ObservedRequest {
    std::string method;
    std::string path;
    std::string authority;
    std::string authorization;
  };

  using Handler = std::function<HTTP2ResponseSpec(const ObservedRequest&)>;

private:

  struct StreamState {
    ObservedRequest request;
    std::string responseStatus;
    std::string responseContentType;
    std::string responseContentLength;
    std::string responseBody;
    size_t responseOffset = 0;
    std::array<nghttp2_nv, 3> responseHeaders = {};
    nghttp2_data_provider responseProvider = {};
    bool responded = false;
  };

  SSL_CTX *context_ = nullptr;
  TLSBase tls_;
  Buffer outbound_ = Buffer(4096, MemoryType::heap);
  Buffer inbound_ = Buffer(4096, MemoryType::heap);
  nghttp2_session *session_ = nullptr;
  bytell_hash_map<int32_t, StreamState> streams_;
  Handler handler_;
  bool ready_ = false;
  bool alpnChecked_ = false;
  bool selectedHTTP2_ = false;
  bool sessionReady_ = false;
  bool sawRequest_ = false;
  std::string failure_;
  ObservedRequest lastRequest_ = {};

  static nghttp2_nv makeHeader(std::string_view name, std::string_view value)
  {
    return {
        reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())),
        reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
        name.size(),
        value.size(),
        NGHTTP2_NV_FLAG_NONE};
  }

  static ssize_t dataSourceReadCallback(nghttp2_session *session,
                                        int32_t streamId,
                                        uint8_t *buffer,
                                        size_t length,
                                        uint32_t *dataFlags,
                                        nghttp2_data_source *source,
                                        void *userData)
  {
    (void)session;
    (void)streamId;
    (void)userData;

    StreamState *stream = static_cast<StreamState *>(source->ptr);
    if (stream == nullptr)
    {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    size_t remaining = stream->responseBody.size() - stream->responseOffset;
    size_t copied = (remaining < length) ? remaining : length;
    if (copied > 0)
    {
      std::memcpy(buffer, stream->responseBody.data() + stream->responseOffset, copied);
      stream->responseOffset += copied;
    }

    if (stream->responseOffset == stream->responseBody.size())
    {
      *dataFlags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return static_cast<ssize_t>(copied);
  }

  static int onBeginHeaders(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            void *userData)
  {
    (void)session;

    InMemoryHTTP2Server *server = static_cast<InMemoryHTTP2Server *>(userData);
    if (server == nullptr)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
    {
      server->streams_.emplace(frame->hd.stream_id, StreamState {});
    }

    return 0;
  }

  static int onHeader(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name,
                      size_t nameLength,
                      const uint8_t *value,
                      size_t valueLength,
                      uint8_t flags,
                      void *userData)
  {
    (void)session;
    (void)flags;

    InMemoryHTTP2Server *server = static_cast<InMemoryHTTP2Server *>(userData);
    if (server == nullptr)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
      return 0;
    }

    auto it = server->streams_.find(frame->hd.stream_id);
    if (it == server->streams_.end())
    {
      return 0;
    }

    std::string_view headerName(reinterpret_cast<const char *>(name), nameLength);
    std::string_view headerValue(reinterpret_cast<const char *>(value), valueLength);
    if (headerName == ":method")
    {
      it->second.request.method.assign(headerValue);
    }
    else if (headerName == ":path")
    {
      it->second.request.path.assign(headerValue);
    }
    else if (headerName == ":authority")
    {
      it->second.request.authority.assign(headerValue);
    }
    else if (headerName == "authorization")
    {
      it->second.request.authorization.assign(headerValue);
    }

    return 0;
  }

  void submitResponse(int32_t streamId)
  {
    auto it = streams_.find(streamId);
    if (it == streams_.end() || it->second.responded)
    {
      return;
    }

    lastRequest_ = it->second.request;
    sawRequest_ = true;

    HTTP2ResponseSpec response = handler_(it->second.request);
    if (response.closeWithoutResponse)
    {
      return;
    }

    it->second.responseStatus = std::to_string(response.status);
    it->second.responseContentType = response.contentType;
    it->second.responseContentLength = std::to_string(response.body.size());
    it->second.responseBody = response.body;
    it->second.responseOffset = 0;
    it->second.responded = true;

    it->second.responseHeaders[0] = makeHeader(":status", it->second.responseStatus);
    it->second.responseHeaders[1] = makeHeader("content-type", it->second.responseContentType);
    it->second.responseHeaders[2] = makeHeader("content-length", it->second.responseContentLength);
    it->second.responseProvider.source.ptr = &it->second;
    it->second.responseProvider.read_callback = dataSourceReadCallback;

    int rc = nghttp2_submit_response(
        session_,
        streamId,
        it->second.responseHeaders.data(),
        it->second.responseHeaders.size(),
        it->second.responseBody.empty() ? nullptr : &it->second.responseProvider);
    if (rc != 0)
    {
      failure_ = "failed to submit in-memory http2 response";
    }
  }

  static int onFrameRecv(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *userData)
  {
    (void)session;

    InMemoryHTTP2Server *server = static_cast<InMemoryHTTP2Server *>(userData);
    if (server == nullptr)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
    {
      if ((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
          frame->hd.type == NGHTTP2_DATA)
      {
        server->submitResponse(frame->hd.stream_id);
      }
    }

    return 0;
  }

  static int onStreamClose(nghttp2_session *session,
                           int32_t streamId,
                           uint32_t errorCode,
                           void *userData)
  {
    (void)session;
    (void)errorCode;

    InMemoryHTTP2Server *server = static_cast<InMemoryHTTP2Server *>(userData);
    if (server == nullptr)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    server->streams_.erase(streamId);
    return 0;
  }

  bool flushPendingWrites(void)
  {
    if (session_ == nullptr)
    {
      return true;
    }

    const uint8_t *data = nullptr;
    while (nghttp2_session_want_write(session_) == 1)
    {
      ssize_t written = nghttp2_session_mem_send(session_, &data);
      if (written < 0)
      {
        failure_ = "failed to emit in-memory http2 bytes";
        return false;
      }
      if (written == 0)
      {
        break;
      }

      outbound_.append(data, static_cast<uint64_t>(written));
    }

    return true;
  }

  void updateSelectedProtocol(void)
  {
    if (alpnChecked_ || tls_.isTLSNegotiated() == false)
    {
      return;
    }

    alpnChecked_ = true;
    const unsigned char *alpn = nullptr;
    unsigned int alpnLength = 0;
    SSL_get0_alpn_selected(tls_.ssl, &alpn, &alpnLength);
    selectedHTTP2_ = (alpnLength == 2 && std::memcmp(alpn, "h2", 2) == 0);
    if (selectedHTTP2_ == false)
    {
      failure_ = "http2 ALPN was not negotiated";
    }
  }

  bool ensureSessionReady(void)
  {
    if (sessionReady_)
    {
      return true;
    }

    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, onBeginHeaders);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, onHeader);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, onFrameRecv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, onStreamClose);

    int rc = nghttp2_session_server_new(&session_, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0 || session_ == nullptr)
    {
      failure_ = "failed to initialize in-memory http2 server session";
      return false;
    }

    if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
    {
      failure_ = "failed to queue in-memory http2 server settings";
      return false;
    }

    sessionReady_ = true;
    return flushPendingWrites();
  }

public:

  explicit InMemoryHTTP2Server(const RuntimeTLSMaterial& tls, Handler handler)
      : context_(createServerContext(tls, true)),
        tls_(context_, true),
        handler_(std::move(handler))
  {
    if (context_ == nullptr)
    {
      return;
    }

    ready_ = true;
  }

  ~InMemoryHTTP2Server()
  {
    if (session_ != nullptr)
    {
      nghttp2_session_del(session_);
      session_ = nullptr;
    }

    if (context_ != nullptr)
    {
      SSL_CTX_free(context_);
      context_ = nullptr;
    }
  }

  bool ready() const
  {
    return ready_;
  }

  TLSBase& tls()
  {
    return tls_;
  }

  Buffer& outbound()
  {
    return outbound_;
  }

  Buffer& inbound()
  {
    return inbound_;
  }

  bool receiveFromClient(void)
  {
    updateSelectedProtocol();
    if (failure_.empty() == false)
    {
      return false;
    }

    if (tls_.isTLSNegotiated() == false)
    {
      return true;
    }

    if (ensureSessionReady() == false)
    {
      return false;
    }

    if (inbound_.outstandingBytes() == 0)
    {
      return true;
    }

    ssize_t readBytes = nghttp2_session_mem_recv(session_, inbound_.pHead(), inbound_.outstandingBytes());
    if (readBytes < 0)
    {
      failure_ = "failed to consume in-memory http2 request bytes";
      return false;
    }
    if (readBytes > 0)
    {
      inbound_.consume(static_cast<uint64_t>(readBytes), true);
    }

    return flushPendingWrites();
  }

  const std::string& failure() const
  {
    return failure_;
  }

  bool selectedHTTP2() const
  {
    return selectedHTTP2_;
  }

  bool sawRequest() const
  {
    return sawRequest_;
  }

  const ObservedRequest& lastRequest() const
  {
    return lastRequest_;
  }
};

static bool initializeClientHTTP2Session(H2NonBlockingClient& client)
{
  nghttp2_session_callbacks *callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, H2NonBlockingClient::on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, H2NonBlockingClient::on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, H2NonBlockingClient::on_stream_close_callback);

  int rc = nghttp2_session_client_new3(&client.session, callbacks, &client, nullptr, nullptr);
  nghttp2_session_callbacks_del(callbacks);
  if (rc != 0 || client.session == nullptr)
  {
    return false;
  }

  nghttp2_settings_entry settings[2] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65536}};
  return nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, settings, 2) == 0;
}

static bool flushClientHTTP2Writes(H2NonBlockingClient& client)
{
  const uint8_t *data = nullptr;
  while (nghttp2_session_want_write(client.session) == 1)
  {
    ssize_t written = nghttp2_session_mem_send(client.session, &data);
    if (written < 0)
    {
      return false;
    }
    if (written == 0)
    {
      break;
    }

    client.wBuffer.append(data, static_cast<uint64_t>(written));
  }

  return true;
}

static bool consumeClientHTTP2Reads(H2NonBlockingClient& client)
{
  if (client.rBuffer.outstandingBytes() > 0)
  {
    ssize_t readBytes = nghttp2_session_mem_recv(client.session, client.rBuffer.pHead(), client.rBuffer.outstandingBytes());
    if (readBytes < 0)
    {
      return false;
    }
    if (readBytes > 0)
    {
      client.rBuffer.consume(static_cast<uint64_t>(readBytes), true);
    }
  }

  if (client.completedTickets.size() > 0)
  {
    for (H2NonBlockingClient::Ticket *ticket : client.completedTickets)
    {
      if (ticket && ticket->coro)
      {
        ticket->coro->co_consume();
      }
    }

    client.completedTickets.clear();
  }

  return true;
}

static bool driveInMemoryHTTP2Exchange(H2NonBlockingClient& client,
                                       InMemoryHTTP2Server& server,
                                       int rounds = 16)
{
  for (int round = 0; round < rounds; ++round)
  {
    bool madeProgress = false;

    if (flushClientHTTP2Writes(client) == false)
    {
      return false;
    }
    if (pumpTLS(client, client.wBuffer, server.tls(), server.inbound(), madeProgress) == false)
    {
      return false;
    }
    if (server.receiveFromClient() == false)
    {
      return false;
    }
    if (pumpTLS(server.tls(), server.outbound(), client, client.rBuffer, madeProgress) == false)
    {
      return false;
    }
    if (consumeClientHTTP2Reads(client) == false)
    {
      return false;
    }

    if (madeProgress == false &&
        client.completedTickets.empty() &&
        client.rBuffer.outstandingBytes() == 0 &&
        server.inbound().outstandingBytes() == 0)
    {
      break;
    }
  }

  return true;
}

class AsyncSSHClientScenario : public SSHClient {
public:

  bool finished = false;
  bool commandFailureObserved = false;
  String commandResponse = {};
  SSHCommandResult failingCommand = {};
  String failingCommandMessage = {};

  void finishScenario(void)
  {
    finished = true;
    if (fd >= 0 && isFixedFile == false)
    {
      SocketBase::close();
      fd = -1;
    }
    Ring::exit = true;
  }

  void run(StringType auto&& user, StringType auto&& privateKeyPath, const String& remotePath)
  {
    String userText = {};
    userText.assign(user);
    String privateKeyPathText = {};
    privateKeyPathText.assign(privateKeyPath);
    String remotePathText = {};
    remotePathText.assign(remotePath);

    uint32_t suspendIndex = nextSuspendIndex();
    connectAndAuthenticate(userText, privateKeyPathText, 15'000);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
    if (failed)
    {
      finishScenario();
      co_return;
    }

    suspendIndex = nextSuspendIndex();
    uploadString("ssh payload"_ctv, remotePathText, 0600, 15'000);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
    if (failed)
    {
      finishScenario();
      co_return;
    }

    String catCommand = {};
    catCommand.snprintf<"cat {}"_ctv>(remotePathText);

    suspendIndex = nextSuspendIndex();
    executeCommand(catCommand, commandResponse, 15'000);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
    if (failed)
    {
      finishScenario();
      co_return;
    }

    suspendIndex = nextSuspendIndex();
    executeCommand("sh -c 'echo boom 1>&2; exit 7'"_ctv, failingCommand, 15'000);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }

    commandFailureObserved = failed;
    if (failed)
    {
      failingCommandMessage.assign(lastFailure);
    }

    suspendIndex = nextSuspendIndex();
    disconnect();
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }

    finishScenario();
  }
};

class ScopedSSHD {
private:

  TempDirectory temp_;
  uint16_t port_ = 0;
  pid_t pid_ = -1;
  std::string hostKeyPath_;
  std::string hostPublicKey_;
  std::string clientKeyPath_;
  std::string authorizedKeysPath_;
  std::string configPath_;
  std::string logPath_;
  std::string remoteRoot_;
  std::string failure_;

  static uint16_t reserveLoopbackPort()
  {
    uint16_t port = 0;
    int fd = createLoopbackListener(port);
    if (fd >= 0)
    {
      close(fd);
    }
    return port;
  }

  static bool waitForPort(uint16_t port, int timeoutMs)
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < deadline)
    {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd >= 0)
      {
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

        int result = connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
        close(fd);

        if (result == 0)
        {
          return true;
        }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return false;
  }

  bool writeSSHKeyPackage(std::string_view basePath, const Vault::SSHKeyPackage& package)
  {
    String privateKeyPath = {};
    privateKeyPath.assign(basePath.data(), basePath.size());
    String publicKeyPath = {};
    publicKeyPath.assign(basePath.data(), basePath.size());
    publicKeyPath.append(".pub"_ctv);

    return writeFile(privateKeyPath, package.privateKeyOpenSSH, 0600) &&
           writeFile(publicKeyPath, package.publicKeyOpenSSH, 0644);
  }

public:

  ScopedSSHD()
  {
    if (!temp_.valid())
    {
      failure_ = "failed to create ssh temp directory";
      return;
    }

    hostKeyPath_ = joinPath(temp_.path(), "host_ed25519_key");
    clientKeyPath_ = joinPath(temp_.path(), "client_ed25519_key");
    authorizedKeysPath_ = joinPath(temp_.path(), "authorized_keys");
    configPath_ = joinPath(temp_.path(), "sshd_config");
    logPath_ = joinPath(temp_.path(), "sshd.log");
    remoteRoot_ = joinPath(temp_.path(), "remote");
    port_ = reserveLoopbackPort();

    if (port_ == 0)
    {
      failure_ = "failed to reserve ssh loopback port";
      return;
    }

    Vault::SSHKeyPackage hostKeys = {};
    Vault::SSHKeyPackage clientKeys = {};
    String keyFailure = {};
    if (Vault::generateSSHKeyPackageEd25519(hostKeys, "sshd-host@basics"_ctv, &keyFailure) == false ||
        Vault::generateSSHKeyPackageEd25519(clientKeys, "client@basics"_ctv, &keyFailure) == false)
    {
      failure_ = "failed to generate ssh keys: " +
                 std::string(reinterpret_cast<const char *>(keyFailure.data()), size_t(keyFailure.size()));
      return;
    }

    if (writeSSHKeyPackage(hostKeyPath_, hostKeys) == false || writeSSHKeyPackage(clientKeyPath_, clientKeys) == false)
    {
      failure_ = "failed to write ssh keys";
      return;
    }

    hostPublicKey_.assign(reinterpret_cast<const char *>(hostKeys.publicKeyOpenSSH.data()), size_t(hostKeys.publicKeyOpenSSH.size()));

    if (!writeFile(std::string_view(authorizedKeysPath_),
                   std::string_view(reinterpret_cast<const char *>(clientKeys.publicKeyOpenSSH.data()),
                                    size_t(clientKeys.publicKeyOpenSSH.size()))))
    {
      failure_ = "failed to write ssh authorized_keys";
      return;
    }

    if (mkdir(remoteRoot_.c_str(), 0700) != 0)
    {
      failure_ = "failed to create ssh remote root";
      return;
    }

    std::string config =
        "Port " + std::to_string(port_) + "\n"
        "ListenAddress 127.0.0.1\n"
        "HostKey " + hostKeyPath_ + "\n"
        "PidFile " + joinPath(temp_.path(), "sshd.pid") + "\n"
        "PermitRootLogin yes\n"
        "PubkeyAuthentication yes\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "ChallengeResponseAuthentication no\n"
        "UsePAM no\n"
        "StrictModes no\n"
        "AuthorizedKeysFile " + authorizedKeysPath_ + "\n"
        "Subsystem sftp internal-sftp\n"
        "LogLevel VERBOSE\n";

    if (!writeFile(configPath_, config))
    {
      failure_ = "failed to write sshd config";
      return;
    }

    pid_ = fork();
    if (pid_ == 0)
    {
      execl("/usr/bin/sshd", "/usr/bin/sshd", "-D", "-e", "-f", configPath_.c_str(), "-E", logPath_.c_str(), nullptr);
      _exit(127);
    }

    if (pid_ < 0)
    {
      failure_ = "failed to fork sshd";
      return;
    }

    if (!waitForPort(port_, 3000))
    {
      failure_ = "sshd did not become ready: " + readFile(logPath_);
      kill(pid_, SIGTERM);
      waitpid(pid_, nullptr, 0);
      pid_ = -1;
    }
  }

  ~ScopedSSHD()
  {
    if (pid_ > 0)
    {
      kill(pid_, SIGTERM);
      waitpid(pid_, nullptr, 0);
      pid_ = -1;
    }
  }

  bool ready() const
  {
    return pid_ > 0 && failure_.empty();
  }

  uint16_t port() const
  {
    return port_;
  }

  const std::string& clientKeyPath() const
  {
    return clientKeyPath_;
  }

  const std::string& hostPublicKey() const
  {
    return hostPublicKey_;
  }

  std::string remoteFilePath(std::string_view leaf) const
  {
    return joinPath(remoteRoot_.c_str(), leaf);
  }

  const std::string& failure() const
  {
    return failure_;
  }
};

struct ReconnectorProbe : Reconnector {
  ReconnectorProbe()
  {
    nDefaultAttemptsBudget = 3;
  }
};

static bool ringSupported()
{
  pid_t child = fork();
  if (child == 0)
  {
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(32, 32, 8, 2, -1, -1, 8);
    Ring::shutdownForExec();
    _exit(0);
  }

  if (child < 0)
  {
    return false;
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0)
  {
    return false;
  }

  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void restoreRingDispatcher()
{
  Ring::interfacer = RingDispatcher::dispatcher;
  Ring::lifecycler = RingDispatcher::dispatcher;
}

static bool ensureTailCapacity(Buffer& buffer, uint64_t moreBytes)
{
  if (buffer.remainingCapacity() >= moreBytes)
  {
    return true;
  }

  return buffer.reserve(buffer.size() + moreBytes);
}

static bool pumpTLS(TLSBase& sender, Buffer& senderBuffer, TLSBase& receiver, Buffer& receiverBuffer, bool& madeProgress)
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

static bool negotiateTLS(TLSBase& client,
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

static void testReconnectorStateMachine(TestSuite& suite)
{
  ReconnectorProbe reconnect;
  reconnect.nAttemptsBudget = 2;
  reconnect.attemptDeadlineMs = 0;
  reconnect.pendingConnect = true;
  EXPECT_FALSE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  reconnect.pendingConnect = true;
  EXPECT_TRUE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  EXPECT_FALSE(suite, reconnect.shouldReconnect());
  EXPECT_TRUE(suite, reconnect.shouldReconnect());

  reconnect.reset();
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  reconnect.connectTimeoutMs = 50;
  reconnect.attemptForMs(25);
  EXPECT_EQ(suite, reconnect.nAttemptsBudget, uint32_t(1));
  reconnect.pendingConnect = true;
  EXPECT_FALSE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  reconnect.pendingConnect = true;
  EXPECT_TRUE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  EXPECT_FALSE(suite, reconnect.shouldReconnect());

  reconnect.reset();
  reconnect.connectTimeoutMs = 10;
  reconnect.nAttemptsBudget = 4;
  reconnect.nConnectionAttempts = 3;
  reconnect.pendingConnect = true;
  reconnect.connectAttemptSucceded();
  EXPECT_FALSE(suite, reconnect.connectAttemptPending());
  EXPECT_EQ(suite, reconnect.nConnectionAttempts, uint32_t(0));
  EXPECT_EQ(suite, reconnect.nAttemptsBudget, uint32_t(0));
  EXPECT_EQ(suite, reconnect.attemptDeadlineMs, int64_t(0));
}

static void runH2NonBlockingScenario(TestSuite& suite,
                                     TestH2NonBlockingClient& client,
                                     HTTP2Server& server)
{
  EXPECT_TRUE(suite, server.ready());
  if (!server.ready())
  {
    return;
  }

  Ring::interfacer = &client;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  Ring::createRing(128, 256, 16, 4, -1, -1, 16);
  client.configure(server.port());
  Ring::installFDIntoFixedFileSlot(&client);
  Ring::queueConnect(&client);
  Ring::start();
  Ring::shutdownForExec();

  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  server.wait();
}

static void testH2NonBlockingClientFlows(TestSuite& suite, const RuntimeTLSMaterial& tls, bool& skipped)
{
  (void)skipped;

  {
    InMemoryHTTP2Server server(tls, [](const InMemoryHTTP2Server::ObservedRequest& request) -> HTTP2ResponseSpec {
      HTTP2ResponseSpec response;
      if (request.path == "/json")
      {
        response.body = "{\"message\":\"async-ok\"}";
      }
      return response;
    });

    EXPECT_TRUE(suite, server.ready());
    if (!server.ready())
    {
      return;
    }

    H2NonBlockingClient client;
    client.authority.assign("127.0.0.1:443"_ctv);
    client.finishSetup("127.0.0.1");

    H2NonBlockingClient::Ticket ticket(nullptr);
    client.queueGet("/json"_ctv, &ticket, H2NonBlockingClient::CleanUpHandler {});

    EXPECT_TRUE(suite, negotiateTLS(client, client.wBuffer, client.rBuffer, server.tls(), server.outbound(), server.inbound()));
    EXPECT_TRUE(suite, client.isTLSNegotiated());
    EXPECT_TRUE(suite, server.tls().isTLSNegotiated());
    EXPECT_TRUE(suite, initializeClientHTTP2Session(client));

    for (H2NonBlockingClient::Request *request : client.requests)
    {
      client.submitRequest(request);
    }

    EXPECT_TRUE(suite, driveInMemoryHTTP2Exchange(client, server));
    EXPECT_TRUE(suite, server.failure().empty());
    EXPECT_TRUE(suite, server.selectedHTTP2());
    EXPECT_TRUE(suite, server.sawRequest());
    EXPECT_EQ(suite, server.lastRequest().path, std::string("/json"));
    EXPECT_EQ(suite, server.lastRequest().authority, std::string("127.0.0.1:443"));
    EXPECT_TRUE(suite, server.lastRequest().authorization.empty());
    EXPECT_EQ(suite, ticket.count, uint32_t(0));
    EXPECT_EQ(suite, ticket.responses.size(), size_t(1));
    if (ticket.responses.size() == 1)
    {
      const H2NonBlockingClient::Response& response = ticket.getResponse();
      EXPECT_EQ(suite, response.statusCode, uint16_t(200));
      EXPECT_STRING_EQ(suite, response.payload, "{\"message\":\"async-ok\"}"_ctv);
    }

    client.connectionBroke();
  }

  {
    H2NonBlockingClient client;
    client.authority.assign("127.0.0.1:443"_ctv);
    client.finishSetup("127.0.0.1");

    WakeTrackingCoroutineStack wakeTracker;
    H2NonBlockingClient::Ticket ticket(&wakeTracker);
    ticket.wakeOnFailure = true;
    client.queueGet("/fail"_ctv, &ticket, H2NonBlockingClient::CleanUpHandler {});

    client.connectionBroke();
    EXPECT_TRUE(suite, wakeTracker.woke);
    EXPECT_EQ(suite, ticket.responses.size(), size_t(0));
  }
}

// BASICS_MULTI_CURL_TLS_NATIVE_BEGIN
class HTTP1TLSServer : public TLSLoopbackServer {
private:

  String body_;
  bool sawRequest_ = false;

protected:

  void handleClient(SSL *ssl) override
  {
    String request;
    if (!sslReadUntilNative(ssl, "\r\n\r\n", request))
    {
      setFailure("failed to read http1 request");
      return;
    }
    sawRequest_ = true;
    static constexpr char http2Preface[] = "PRI * HTTP/2.0";
    if (request.size() >= sizeof(http2Preface) - 1 &&
        std::memcmp(request.data(), http2Preface, sizeof(http2Preface) - 1) == 0)
    {
      return;
    }
    String response;
    response.snprintf<"HTTP/1.1 200 OK\r\nContent-Length: {itoa}\r\nConnection: close\r\n\r\n"_ctv>(
        uint64_t(body_.size()));
    response.append(body_);
    if (!sslWriteAllNative(ssl, response))
    {
      setFailure("failed to write http1 response");
    }
  }

public:

  HTTP1TLSServer(const RuntimeTLSMaterial& tls, String body)
      : TLSLoopbackServer(tls, false), body_(std::move(body))
  {}

  bool sawRequest() const
  {
    return sawRequest_;
  }
};

struct CurlTlsScenario final : RingMultiplexer {
  MultiCurlClient *client = nullptr;
  TimeoutPacket guard;
  MultiCurlClient::Result result;
  bool guardArmed = false;
  bool guardCancellationRequested = false;
  bool timedOut = false;
  uint32_t callbacks = 0;

  CurlTlsScenario()
  {
    guard.originator = this;
  }

  static void completed(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& completion)
  {
    CurlTlsScenario& scenario = *static_cast<CurlTlsScenario *>(context);
    ++scenario.callbacks;
    scenario.result = std::move(completion);
    (void)scenario.client->shutdown();
    if (scenario.guardArmed && !scenario.guardCancellationRequested)
    {
      scenario.guardCancellationRequested = true;
      Ring::queueCancelTimeout(&scenario.guard);
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int resultCode) override
  {
    if (packet != &guard)
    {
      return;
    }
    guardArmed = false;
    guardCancellationRequested = false;
    guard.clear();
    if (resultCode != -ECANCELED)
    {
      timedOut = true;
      (void)client->shutdown();
    }
    if (client->shutdownSafe())
    {
      Ring::exit = true;
    }
  }

  void completionBatchHandler(uint32_t) override
  {
    if (client->shutdownSafe() && !guardArmed)
    {
      Ring::exit = true;
    }
  }
};

static MultiCurlClient::Request curlTlsRequest(const RuntimeTLSMaterial& tls,
                                                   const char *host,
                                                   uint16_t port,
                                                   MultiCurlClient::HttpPolicy policy,
                                                   bool trustFixture)
{
  String url;
  url.append("https://"_ctv);
  url.append(host);
  url.append(':');
  url.append(String(port));
  url.append("/tls"_ctv);
  String service(port);
  MultiCurlClient::Request request;
  request.url = std::move(url);
  request.resolveHost.assign("127.0.0.1"_ctv);
  request.authority.assign(host);
  request.httpPolicy = policy;
  request.tlsMinimum = MultiCurlClient::TlsMinimum::tls13;
  request.family = AsyncDnsResolver::Family::ipv4;
  request.responseBytes = 4_KB;
  request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);
  request.originPolicy.requiredScheme.assign("https"_ctv);
  request.originPolicy.requiredHost.assign(host);
  request.originPolicy.requiredAuthority.assign(host);
  request.originPolicy.requiredService.assign(service);
  request.originPolicy.requiredResolveHost.assign("127.0.0.1"_ctv);
  if (trustFixture)
  {
    request.caSource = MultiCurlClient::CaSource::file;
    request.caFile.assign(tls.certPath().data(), tls.certPath().size());
  }
  return request;
}

static MultiCurlClient::Result runCurlTlsRequest(TestSuite& suite,
                                                     MultiCurlClient::Request request)
{
  RingInterface *previousInterfacer = Ring::interfacer;
  RingLifecycle *previousLifecycler = Ring::lifecycler;
  RingDispatcher *previousDispatcher = RingDispatcher::dispatcher;
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  RingDispatcher::dispatcher = nullptr;
  RingDispatcher dispatcher;
  Ring::createRing(128, 256, 8, 2, -1, -1, 8);

  CurlTlsScenario scenario;
  RingDispatcher::installMultiplexee(&scenario, &scenario);
  RingDispatcher::installMultiplexer(&scenario);
  scenario.client = new MultiCurlClient();
  EXPECT_TRUE(suite, scenario.client->ready());
  scenario.guard.setTimeoutSeconds(5);
  scenario.guardArmed = true;
  Ring::queueTimeout(&scenario.guard);
  scenario.client->submit(std::move(request), {&scenario, CurlTlsScenario::completed});
  Ring::start();

  EXPECT_FALSE(suite, scenario.timedOut);
  EXPECT_EQ(suite, scenario.callbacks, uint32_t(1));
  EXPECT_TRUE(suite, scenario.client->shutdownSafe());
  MultiCurlClient::Result result = std::move(scenario.result);
  delete scenario.client;
  RingDispatcher::eraseMultiplexee(&scenario);
  Ring::shutdownForExec();
  Ring::interfacer = previousInterfacer;
  Ring::lifecycler = previousLifecycler;
  Ring::exit = false;
  Ring::shuttingDown = false;
  RingDispatcher::dispatcher = previousDispatcher;
  return result;
}

static void testCurlTlsAndProtocolPolicies(TestSuite& suite,
                                           const RuntimeTLSMaterial& tls,
                                           const RuntimeTLSMaterial& expiredTls,
                                           bool& skipped)
{
  if (!ringSupported())
  {
    skipped = true;
    std::cout << "protocol client tests: skipping Curl TLS coverage because required io_uring features are unavailable.\n";
    return;
  }

  {
    HTTP2Server server(tls, [](const HTTP2Server::ObservedRequest&) {
      HTTP2ResponseSpec response;
      response.body = "h2-ok";
      return response;
    });
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(tls, "localhost", server.port(),
                       MultiCurlClient::HttpPolicy::requireHttp2, true));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::success);
    EXPECT_EQ(suite, result.httpVersion, long(CURL_HTTP_VERSION_2_0));
    EXPECT_STRING_EQ(suite, result.body, "h2-ok"_ctv);
    EXPECT_TRUE(suite, server.failure().empty());
    EXPECT_TRUE(suite, server.selectedHTTP2());
    EXPECT_TRUE(suite, server.sawRequest());
  }

  {
    HTTP1TLSServer server(tls, "h1-ok");
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(tls, "localhost", server.port(),
                       MultiCurlClient::HttpPolicy::preferHttp2, true));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::success);
    EXPECT_EQ(suite, result.httpVersion, long(CURL_HTTP_VERSION_1_1));
    EXPECT_STRING_EQ(suite, result.body, "h1-ok"_ctv);
    EXPECT_TRUE(suite, server.failure().empty());
    EXPECT_TRUE(suite, server.sawRequest());
  }

  {
    HTTP1TLSServer server(tls, "rejected");
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(tls, "localhost", server.port(),
                       MultiCurlClient::HttpPolicy::requireHttp2, true));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::httpVersionRejected);
    EXPECT_FALSE(suite, server.sawRequest());
  }

  {
    HTTP2Server server(tls, [](const HTTP2Server::ObservedRequest&) {
      return HTTP2ResponseSpec {};
    });
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(tls, "localhost", server.port(),
                       MultiCurlClient::HttpPolicy::requireHttp2, false));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::transportFailure);
  }

  {
    HTTP2Server server(expiredTls, [](const HTTP2Server::ObservedRequest&) {
      return HTTP2ResponseSpec {};
    });
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(expiredTls, "localhost", server.port(),
                       MultiCurlClient::HttpPolicy::requireHttp2, true));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::transportFailure);
    EXPECT_EQ(suite, result.curlCode, CURLcode(CURLE_PEER_FAILED_VERIFICATION));
  }

  {
    HTTP2Server server(tls, [](const HTTP2Server::ObservedRequest&) {
      return HTTP2ResponseSpec {};
    });
    EXPECT_TRUE(suite, server.ready());
    MultiCurlClient::Result result = runCurlTlsRequest(
        suite,
        curlTlsRequest(tls, "wrong-host.test", server.port(),
                       MultiCurlClient::HttpPolicy::requireHttp2, true));
    server.wait();
    EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::transportFailure);
  }
}
// BASICS_MULTI_CURL_TLS_NATIVE_END

static void testSSHClientLoopback(TestSuite& suite, bool& skipped)
{
  if (!ringSupported())
  {
    skipped = true;
    std::cout << "protocol client tests: skipping SSH coverage because required io_uring features are unavailable.\n";
    return;
  }

  ScopedSSHD sshd;
  if (!sshd.ready())
  {
    skipped = true;
    std::cout << "protocol client tests: skipping SSH coverage because sshd could not be started: " << sshd.failure() << '\n';
    return;
  }

  AsyncSSHClientScenario client;
  client.setIPVersion(AF_INET);
  client.setDaddr("127.0.0.1"_ctv, sshd.port());
  client.configureExpectedHostKey("127.0.0.1"_ctv, sshd.port(), String(sshd.hostPublicKey().c_str()));

  restoreRingDispatcher();
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(128, 256, 16, 4, -1, -1, 16);

  client.run("root"_ctv, String(sshd.clientKeyPath().c_str()), String(sshd.remoteFilePath("uploaded.txt").c_str()));

  Ring::start();
  Ring::shutdownForExec();

  restoreRingDispatcher();
  Ring::exit = false;
  Ring::shuttingDown = false;

  EXPECT_TRUE(suite, client.finished);
  EXPECT_FALSE(suite, client.failed);
  EXPECT_STRING_EQ(suite, client.commandResponse, "ssh payload"_ctv);
  EXPECT_TRUE(suite, client.commandFailureObserved);
  EXPECT_EQ(suite, client.failingCommand.exitStatus, 7);
  EXPECT_TRUE(suite, stringViewOf(client.failingCommand.stderrOutput).find("boom") != std::string_view::npos);
  EXPECT_TRUE(suite, stringViewOf(client.failingCommandMessage).find("boom") != std::string_view::npos);
}

static void testSSHClientRejectsMismatchedHostKey(TestSuite& suite, bool& skipped)
{
  if (!ringSupported())
  {
    skipped = true;
    std::cout << "protocol client tests: skipping SSH host-key mismatch coverage because required io_uring features are unavailable.\n";
    return;
  }

  ScopedSSHD sshd;
  if (!sshd.ready())
  {
    skipped = true;
    std::cout << "protocol client tests: skipping SSH host-key mismatch coverage because sshd could not be started: " << sshd.failure() << '\n';
    return;
  }

  AsyncSSHClientScenario client;
  client.setIPVersion(AF_INET);
  client.setDaddr("127.0.0.1"_ctv, sshd.port());
  String mismatchedHostKey = {};
  {
    std::string mismatchedHostKeyText = readFile(sshd.clientKeyPath() + ".pub");
    mismatchedHostKey.assign(mismatchedHostKeyText.data(), mismatchedHostKeyText.size());
  }
  client.configureExpectedHostKey("127.0.0.1"_ctv, sshd.port(), mismatchedHostKey);

  restoreRingDispatcher();
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(128, 256, 16, 4, -1, -1, 16);

  client.run("root"_ctv, String(sshd.clientKeyPath().c_str()), String(sshd.remoteFilePath("uploaded.txt").c_str()));

  Ring::start();
  Ring::shutdownForExec();

  restoreRingDispatcher();
  Ring::exit = false;
  Ring::shuttingDown = false;

  EXPECT_TRUE(suite, client.finished);
  EXPECT_TRUE(suite, client.failed);
  EXPECT_TRUE(suite, stringViewOf(client.lastFailure).find("host key mismatch") != std::string_view::npos);
}

} // namespace

int main()
{
  TestSuite suite;
  bool skipped = false;

  RuntimeTLSMaterial tls;
  RuntimeTLSMaterial expiredTls(true);
  EXPECT_TRUE(suite, tls.ready());
  EXPECT_TRUE(suite, expiredTls.ready());
  if (!tls.ready() || !expiredTls.ready())
  {
    return suite.finish("protocol client tests");
  }

  testReconnectorStateMachine(suite);
  testH2NonBlockingClientFlows(suite, tls, skipped);
  testCurlTlsAndProtocolPolicies(suite, tls, expiredTls, skipped);
  testSSHClientLoopback(suite, skipped);
  testSSHClientRejectsMismatchedHostKey(suite, skipped);

  if (skipped)
  {
    std::cout << "protocol client tests completed with host-specific skips.\n";
  }

  return suite.finish("protocol client tests");
}
