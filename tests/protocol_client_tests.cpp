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
#include <unordered_map>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
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
#include "networking/email.client.h"
#include "networking/h2b.client.h"
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

public:

  RuntimeTLSMaterial()
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
    if (data.size() >= terminator.size() &&
        data.rfind(terminator) == (data.size() - terminator.size()))
    {
      return true;
    }
  }
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

class SMTPServer : public TLSLoopbackServer {
private:

  std::vector<std::string> commands_;
  std::string messageData_;

protected:

  void handleClient(SSL *ssl) override
  {
    if (!sslWriteAll(ssl, "220 basics-smtp ESMTP ready\r\n"))
    {
      setFailure("failed to send smtp greeting");
      return;
    }

    while (true)
    {
      std::string line;
      if (!sslReadLine(ssl, line))
      {
        break;
      }

      commands_.push_back(line);

      if (line.rfind("EHLO ", 0) == 0 || line.rfind("HELO ", 0) == 0)
      {
        if (!sslWriteAll(ssl, "250-localhost\r\n250 SIZE 1048576\r\n"))
        {
          setFailure("failed to reply to smtp greeting");
          return;
        }
      }
      else if (line.rfind("MAIL FROM:", 0) == 0 || line.rfind("RCPT TO:", 0) == 0)
      {
        if (!sslWriteAll(ssl, "250 OK\r\n"))
        {
          setFailure("failed to reply to smtp envelope command");
          return;
        }
      }
      else if (line == "DATA\r\n")
      {
        if (!sslWriteAll(ssl, "354 End data with <CR><LF>.<CR><LF>\r\n"))
        {
          setFailure("failed to reply to smtp DATA");
          return;
        }

        if (!sslReadUntil(ssl, "\r\n.\r\n", messageData_))
        {
          setFailure("failed to read smtp message payload");
          return;
        }

        if (messageData_.size() >= 5)
        {
          messageData_.erase(messageData_.size() - 5);
        }

        if (!sslWriteAll(ssl, "250 OK queued\r\n"))
        {
          setFailure("failed to acknowledge smtp payload");
          return;
        }
      }
      else if (line == "QUIT\r\n")
      {
        (void)sslWriteAll(ssl, "221 Bye\r\n");
        break;
      }
      else
      {
        if (!sslWriteAll(ssl, "250 OK\r\n"))
        {
          setFailure("failed to reply to smtp command");
          return;
        }
      }
    }
  }

public:

  explicit SMTPServer(const RuntimeTLSMaterial& tls)
      : TLSLoopbackServer(tls, false)
  {}

  const std::vector<std::string>& commands() const
  {
    return commands_;
  }

  const std::string& messageData() const
  {
    return messageData_;
  }
};

struct HTTPResponseSpec {
  int status = 200;
  std::string contentType = "application/json";
  std::string body;
};

class HTTPServer : public TLSLoopbackServer {
public:

  struct ObservedRequest {
    std::string method;
    std::string path;
    std::string authority;
    std::string authorization;
  };

  using Handler = std::function<HTTPResponseSpec(const ObservedRequest&)>;

private:

  Handler handler_;
  ObservedRequest lastRequest_;
  bool sawRequest_ = false;

protected:

  void handleClient(SSL *ssl) override
  {
    std::string request;
    if (!sslReadUntil(ssl, "\r\n\r\n", request))
    {
      setFailure("failed to read https request");
      return;
    }

    size_t lineEnd = request.find("\r\n");
    if (lineEnd == std::string::npos)
    {
      setFailure("invalid https request line");
      return;
    }

    std::string_view requestLine(request.data(), lineEnd);
    size_t methodEnd = requestLine.find(' ');
    size_t pathEnd = (methodEnd == std::string::npos) ? std::string_view::npos : requestLine.find(' ', methodEnd + 1);
    if (methodEnd == std::string::npos || pathEnd == std::string_view::npos)
    {
      setFailure("malformed https request line");
      return;
    }

    sawRequest_ = true;
    lastRequest_.method.assign(requestLine.substr(0, methodEnd));
    lastRequest_.path.assign(requestLine.substr(methodEnd + 1, pathEnd - methodEnd - 1));

    HTTPResponseSpec response = handler_(lastRequest_);
    std::string payload =
        "HTTP/1.1 " + std::to_string(response.status) + " OK\r\n"
        "Content-Type: " + response.contentType + "\r\n"
        "Content-Length: " + std::to_string(response.body.size()) + "\r\n"
        "Connection: close\r\n\r\n" +
        response.body;

    if (!sslWriteAll(ssl, payload))
    {
      setFailure("failed to write https response");
    }
  }

public:

  HTTPServer(const RuntimeTLSMaterial& tls, Handler handler)
      : TLSLoopbackServer(tls, false),
        handler_(std::move(handler))
  {}

  bool sawRequest() const
  {
    return sawRequest_;
  }

  const ObservedRequest& lastRequest() const
  {
    return lastRequest_;
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
  std::unordered_map<int32_t, StreamState> streams_;
  std::unordered_map<int32_t, std::unique_ptr<ResponseState>> responses_;
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

class ExposedH2BlockingClient : public H2BlockingClient {
public:

  using H2BlockingClient::getJSONResponse;
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
    setIPv4FromURI("127.0.0.1", port);

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
  std::unordered_map<int32_t, StreamState> streams_;
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
      server->streams_.try_emplace(frame->hd.stream_id);
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
  EXPECT_FALSE(suite, reconnect.connectAttemptFailed());
  EXPECT_TRUE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.shouldReconnect());
  EXPECT_TRUE(suite, reconnect.shouldReconnect());

  reconnect.reset();
  reconnect.connectTimeoutMs = 50;
  reconnect.attemptForMs(25);
  EXPECT_EQ(suite, reconnect.nAttemptsBudget, uint32_t(1));
  EXPECT_FALSE(suite, reconnect.connectAttemptFailed());
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  EXPECT_TRUE(suite, reconnect.connectAttemptFailed());
  EXPECT_FALSE(suite, reconnect.shouldReconnect());

  reconnect.reset();
  reconnect.connectTimeoutMs = 10;
  reconnect.nAttemptsBudget = 4;
  reconnect.nConnectionAttempts = 3;
  reconnect.connectAttemptSucceded();
  EXPECT_EQ(suite, reconnect.nConnectionAttempts, uint32_t(0));
  EXPECT_EQ(suite, reconnect.nAttemptsBudget, uint32_t(0));
  EXPECT_EQ(suite, reconnect.attemptDeadlineMs, int64_t(0));
}

static void testEmailClientSMTPFlow(TestSuite& suite, const RuntimeTLSMaterial& tls)
{
  SMTPServer server(tls);
  EXPECT_TRUE(suite, server.ready());
  if (!server.ready())
  {
    return;
  }

  {
    EmailClient client;
    std::string smtpUrl = "smtps://127.0.0.1:" + std::to_string(server.port());
    client.setTLSCAFile(tls.certPath());
    client.setSMTP(smtpUrl);
    client.sendEmail(
        "sender@example.com"_ctv,
        "recipient@example.com"_ctv,
        "Protocol Test"_ctv,
        "This body is intentionally long so that the email client has to wrap it onto multiple lines while preserving the message contents."_ctv);
  }

  server.wait();

  if (!server.failure().empty())
  {
    std::cerr << "smtp server failure: " << server.failure() << '\n';
  }

  EXPECT_TRUE(suite, server.failure().empty());
  EXPECT_TRUE(suite, !server.commands().empty());
  EXPECT_TRUE(suite, server.messageData().find("Subject: Protocol Test\r\n") != std::string::npos);
  EXPECT_TRUE(suite, server.messageData().find("To: recipient@example.com\r\n") != std::string::npos);
  EXPECT_TRUE(suite, server.messageData().find("From: ") != std::string::npos);
  EXPECT_TRUE(suite, server.messageData().find("This body is intentionally long") != std::string::npos);

  bool sawMailFrom = false;
  bool sawRcptTo = false;
  bool sawData = false;
  for (const std::string& command : server.commands())
  {
    sawMailFrom = sawMailFrom || (command.rfind("MAIL FROM:", 0) == 0);
    sawRcptTo = sawRcptTo || (command.rfind("RCPT TO:", 0) == 0);
    sawData = sawData || (command == "DATA\r\n");
  }

  EXPECT_TRUE(suite, sawMailFrom);
  EXPECT_TRUE(suite, sawRcptTo);
  EXPECT_TRUE(suite, sawData);
}

static void testH2BlockingClientJSONAndParseFailure(TestSuite& suite, const RuntimeTLSMaterial& tls)
{
  {
    HTTPServer server(tls, [](const HTTPServer::ObservedRequest& request) -> HTTPResponseSpec {
      HTTPResponseSpec response;
      if (request.path == "/json")
      {
        response.body = "{\"message\":\"ok\"}";
      }
      else
      {
        response.body = "{\"unexpected\":true}";
      }
      return response;
    });

    EXPECT_TRUE(suite, server.ready());
    if (server.ready())
    {
      ExposedH2BlockingClient client;
      client.setTLSCAFile(tls.certPath());
      std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/json";
      auto result = client.getJSONResponse(url);
      EXPECT_TRUE(suite, !result.error());
      if (!result.error())
      {
        simdjson::dom::element element;
        EXPECT_TRUE(suite, !result.get(element));
        std::string_view message;
        EXPECT_TRUE(suite, !element["message"].get(message));
        EXPECT_EQ(suite, message, std::string_view("ok"));
      }

      server.wait();
      if (!server.failure().empty())
      {
        std::cerr << "https server failure (/json): " << server.failure() << '\n';
      }
      EXPECT_TRUE(suite, server.failure().empty());
      EXPECT_TRUE(suite, server.sawRequest());
      EXPECT_EQ(suite, server.lastRequest().path, std::string("/json"));
      EXPECT_EQ(suite, server.lastRequest().method, std::string("GET"));
    }
  }

  {
    HTTPServer server(tls, [](const HTTPServer::ObservedRequest& request) -> HTTPResponseSpec {
      HTTPResponseSpec response;
      if (request.path == "/invalid")
      {
        response.body = "not-json";
      }
      return response;
    });

    EXPECT_TRUE(suite, server.ready());
    if (server.ready())
    {
      ExposedH2BlockingClient client;
      client.setTLSCAFile(tls.certPath());
      std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/invalid";
      auto result = client.getJSONResponse(url);
      EXPECT_TRUE(suite, result.error() != simdjson::SUCCESS);

      server.wait();
      if (!server.failure().empty())
      {
        std::cerr << "https server failure (/invalid): " << server.failure() << '\n';
      }
      EXPECT_TRUE(suite, server.failure().empty());
      EXPECT_TRUE(suite, server.sawRequest());
      EXPECT_EQ(suite, server.lastRequest().path, std::string("/invalid"));
    }
  }
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

} // namespace

int main()
{
  TestSuite suite;
  bool skipped = false;

  RuntimeTLSMaterial tls;
  EXPECT_TRUE(suite, tls.ready());
  if (!tls.ready())
  {
    return suite.finish("protocol client tests");
  }

  testReconnectorStateMachine(suite);
  testEmailClientSMTPFlow(suite, tls);
  testH2BlockingClientJSONAndParseFailure(suite, tls);
  testH2NonBlockingClientFlows(suite, tls, skipped);
  testSSHClientLoopback(suite, skipped);

  if (skipped)
  {
    std::cout << "protocol client tests completed with host-specific skips.\n";
  }

  return suite.finish("protocol client tests");
}
