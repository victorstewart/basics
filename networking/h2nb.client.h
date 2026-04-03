// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nghttp2/nghttp2.h>
#include <itoa/jeaiii_to_text.h>
#include <SG14/inplace_function.h>
#include <networking/tls.h>

// at the moment none of these require pausing execution of the coroutine, thus we provide no mechanism to report back the result or response. but could easily add that back.
class H2NonBlockingClient : public RingInterface, public TCPStream, public TLSBase {
public:

  typedef stdext::inplace_function<void(void), 250> CleanUpHandler;

  class Response {
  public:

    uint16_t statusCode = 0;
    String payload;

    bool success(void) const
    {
      return (statusCode >= 200) && (statusCode < 300);
    }
  };

  class Ticket {
  public:

    bytell_hash_map<int32_t, Response> responses; // by streamID
    CoroutineStack *coro;
    uint32_t count;
    bool wakeOnFailure = false;

    const Response& getResponse(void)
    {
      return responses.begin()->second;
    }

    bool connectionFailed(void)
    {
      return (responses.size() == 0);
    }

    void clear(void)
    {
      responses.clear();
      count = 0;
    }

    Ticket(CoroutineStack *_coro)
        : coro(_coro),
          count(0)
    {}
  };

private:

  Vector<Ticket *> completedTickets;

  void clearPendingRequests(bool wakeOnFailure)
  {
    while (requests.size())
    {
      auto it = requests.begin();
      Request *request = *it;
      requests.erase(it);

      if (request->ticket && request->ticket->count > 0)
      {
        request->ticket->count--;
        if (wakeOnFailure && request->ticket->count == 0 && request->ticket->wakeOnFailure && request->ticket->coro)
        {
          request->ticket->coro->co_consume();
        }
      }

      delete request;
    }
  }

  static SSL_CTX *getHTTP2TLSCtx(void)
  {
    struct ssl_ctx_st *context = SSL_CTX_new(TLS_method());
    SSL_CTX_set_alpn_protos(context, (const unsigned char *)"\x02h2", 3);
    SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);

    return context;
  }

  struct Request {

    Vector<nghttp2_nv> headers;
    nghttp2_data_provider dataProvider;
    CleanUpHandler cleanUp;
    Buffer *data;
    Ticket *ticket;
    String contentLength;
    bytell_hash_set<Request *> *container;
    int32_t streamID;

    Request()
        : dataProvider({}),
          data(nullptr),
          ticket(nullptr),
          contentLength(8, MemoryType::heap),
          container(nullptr),
          streamID(0)
    {}

    ~Request()
    {
      if (cleanUp)
      {
        cleanUp();
      }
    }
  };

  // response headers
  static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
  {
    (void)flags;
    (void)user_data;

    // use this to accumulate headers for a request if we want to
    int32_t stream_id = frame->hd.stream_id;
    Request *request = (Request *)nghttp2_session_get_stream_user_data(session, stream_id);
    if (request == nullptr)
    {
      return 0;
    }

    if (request->ticket)
    {
      String headerName;
      headerName.setInvariant(name, namelen);

      if (headerName == ":status"_ctv || headerName == "status"_ctv)
      {
        String headerValue;
        headerValue.setInvariant(value, valuelen);

        Response& response = request->ticket->responses.atOrConstruct(stream_id);
        response.statusCode = headerValue.toNumber<uint16_t>();
      }
    }

    return 0;
  }

  // response data
  static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
  {
    (void)flags;
    (void)user_data;

    Request *request = (Request *)nghttp2_session_get_stream_user_data(session, stream_id);
    if (request == nullptr)
    {
      return 0;
    }

    if (request->ticket)
    {
      request->ticket->responses.atOrConstruct(stream_id).payload.append(data, len);
    }

    return 0;
  }

  static int on_stream_close_callback(nghttp2_session *session, int stream_id, unsigned int error_code, void *user_data)
  {
    (void)session;

    H2NonBlockingClient *client = (H2NonBlockingClient *)user_data;
    Request *request = (Request *)nghttp2_session_get_stream_user_data(session, stream_id);
    if (request == nullptr)
    {
      return 0;
    }

    request->container->erase(request);

    if (error_code == NGHTTP2_NO_ERROR)
    {
      if (request->ticket)
      {
        if (request->ticket->count > 0)
        {
          request->ticket->count--;
        }

        if (request->ticket->count == 0 && client != nullptr)
        {
          client->completedTickets.push_back(request->ticket);
        }
      }
    }

    delete request; // cleanUp will be called here

    return 0;
  }

  void send(bool wasTLSNegotiated)
  {
    if (wasTLSNegotiated)
    {
      if (session)
      {
        const uint8_t *data;
        int nread;

        while (nghttp2_session_want_write(session) == 1)
        {
          nread = nghttp2_session_mem_send(session, &data);
          if (nread > 0)
          {
            wBuffer.append(data, nread);
          }
        }
      }
    }

    encryptInto(wBuffer);
    if (wBuffer.outstandingBytes() > 0)
    {
      Ring::queueSend(this);
    }

    Ring::queueRecv(this);
  }

public:

  virtual uint32_t nBytesToSend(void)
  {
    return TLSBase::nEncryptedBytesToSend;
  }

private:

  static ssize_t nghttp2_data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
  {
    Buffer *data = (Buffer *)source->ptr;

    uint32_t bytesToWrite = data->outstandingBytes() > length ? length : data->outstandingBytes();

    memcpy(buf, data->pHead(), bytesToWrite);

    data->consume(bytesToWrite, true);

    if (data->outstandingBytes() == 0)
    {
      *data_flags = NGHTTP2_FLAG_END_STREAM;
    }

    return bytesToWrite;
  }

  void submitRequest(Request *request)
  {

    // for (auto header : request->headers)
    // {
    // }

    // if (request->contentLength.size())
    // {
    // 	Buffer *data = (Buffer *)request->dataProvider.source.ptr;
    // }

    request->streamID = nghttp2_submit_request(session, nullptr, request->headers.data(), request->headers.size(), (request->contentLength.size() ? &request->dataProvider : nullptr), request);
  }

  template <typename Path, typename Method, typename... Headers>
  void queue(Path&& path, Method&& method, Buffer *data, Ticket *ticket, CleanUpHandler&& cleanUp, Headers&&...headers)
  {
    Request *request = new Request();
    request->cleanUp = std::move(cleanUp);
    request->container = &requests;
    request->ticket = ticket;
    if (request->ticket)
    {
      request->ticket->count++;
    }

    request->headers.push_back(make_header(":method"_ctv, method));

    if constexpr (std::is_pointer_v<Path>)
    {
      request->headers.push_back(make_header(":path"_ctv, *path));
    }
    else
    {
      request->headers.push_back(make_header(":path"_ctv, path));
    }

    request->headers.push_back(make_header(":scheme"_ctv, "https"_ctv));
    if (authority.size())
    {
      request->headers.push_back(make_header(":authority"_ctv, authority));
    }
    request->headers.push_back(make_header("user-agent"_ctv, "curl/7.76.1"_ctv));
    request->headers.push_back(make_header("accept"_ctv, "*/*"_ctv));
    if (credentials.size())
    {
      request->headers.push_back(make_header("authorization"_ctv, credentials));
    }

    (request->headers.push_back(headers), ...);

    if (data)
    {
      request->data = data;

      uint8_t *end = (uint8_t *)jeaiii::to_text_from_integer((char *)request->contentLength.data(), (uint32_t)data->size());
      request->contentLength.advance(end - request->contentLength.data());

      request->headers.push_back(make_header("content-length"_ctv, request->contentLength));
      request->dataProvider.source.ptr = data;
      request->dataProvider.read_callback = nghttp2_data_source_read_callback;
    }

    if (isTLSNegotiated() == true)
    {
      submitRequest(request);
      send(true);
    }

    requests.insert(request);
  }

  bytell_hash_set<Request *> requests;
  nghttp2_session *session = nullptr;
  SSL_CTX *tlsctx = nullptr;

  template <typename Path, typename... Headers>
  void queuePost(Path&& path, Buffer *data, Ticket *ticket, CleanUpHandler&& cleanUp, Headers&&...headers)
  {
    queue(std::forward<Path>(path), "POST"_ctv, data, ticket, std::forward<CleanUpHandler>(cleanUp), std::forward<Headers>(headers)...);
  }

  bool isFailed = false;

public:

  String credentials;
  String authority;

  template <typename StringTypeA, typename StringTypeB>
  static nghttp2_nv make_header(StringTypeA&& headerName, StringTypeB&& headerValue)
  {
    return {(uint8_t *)headerName.data(), (uint8_t *)headerValue.data(), headerName.size(), headerValue.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE};
  }

  template <typename Path, typename... Headers>
  void queuePostJSON(Path&& path, Buffer *data, Ticket *ticket, CleanUpHandler&& cleanUp, Headers&&...headers)
  {

    queuePost(std::forward<Path>(path), data, ticket, std::forward<CleanUpHandler>(cleanUp), make_header("content-type"_ctv, "application/json"_ctv), std::forward<Headers>(headers)...);
  }

  // template <typename Path, typename... Headers>
  // void queuePostEncoded(Path&& path, Buffer *data, Headers&&... headers)
  // {
  // 	queuePost(std::forward<Path>(path), data, nullptr, nullptr, make_header("content-type"_ctv, "application/x-www-form-urlencoded"_ctv), std::forward<Headers>(headers)...);
  // }

  template <typename Path, typename... Headers>
  void queueGet(Path&& path, Ticket *ticket, CleanUpHandler&& cleanUp, Headers&&...headers)
  {
    queue(std::forward<Path>(path), "GET"_ctv, nullptr, ticket, std::forward<CleanUpHandler>(cleanUp), std::forward<Headers>(headers)...);
  }

  void sendTLSClientHello(void)
  {
    send(false);
  }

  void cancelRequest(Ticket *ticket)
  {
    for (auto it = requests.begin(); it != requests.end(); it++)
    {
      Request *request = *it;

      if (request->ticket)
      {
        if (request->ticket == ticket)
        {
          requests.erase(it);
          break;
        }
      }
    }
  }

  void connectionBroke(void)
  {
    if (session)
    {
      nghttp2_session_del(session);
      session = nullptr;
    }

    TLSBase::resetTLS();
    clearPendingRequests(true);
    completedTickets.clear();
  }

  bool isConnected(void)
  {
    return isTLSNegotiated();
  }

  virtual void connected(void) {}

  bool recv(uint32_t bytesRecved)
  {
    bool wasTLSNegotiated = isTLSNegotiated();

    if (unlikely(decryptFrom(rBuffer, bytesRecved) == false))
    {
      return false;
    }

    if (isTLSNegotiated() == true)
    {
      // just established or reestablisehd TLS connection
      if (unlikely(wasTLSNegotiated == false))
      {
        nghttp2_session_callbacks *callbacks;

        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

        nghttp2_session_client_new3(&session, callbacks, this, NULL, NULL);

        nghttp2_session_callbacks_del(callbacks);

        nghttp2_settings_entry iv[3] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100   },
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    65'536}
        };

        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 2);

        send(false); // complete final leg of the TLS handshake

        setConnected();

        // might have pending requests to send
        if (requests.size())
        {
          for (Request *request : requests)
          {
            submitRequest(request);
          }
        }

        connected();
      }

      if (rBuffer.outstandingBytes())
      {
        ssize_t readlen = nghttp2_session_mem_recv(session, rBuffer.pHead(), rBuffer.outstandingBytes());

        if (readlen > 0)
        {
          rBuffer.consume(readlen, true);
        }
      }

      if (completedTickets.size())
      {
        for (Ticket *ticket : completedTickets)
        {
          if (ticket->coro)
          {
            ticket->coro->co_consume();
          }
        }

        completedTickets.clear();
      }
    }
    else
    {
      send(false);
    }

    return true;
  }

  void setTLSClientCertificate(const char *cert_file_path)
  {
    int result = SSL_CTX_use_certificate_file(tlsctx, cert_file_path, SSL_FILETYPE_PEM);
    (void)result;
  }

  void setTLSClientKey(const char *key_file_path)
  {
    int result = SSL_CTX_use_PrivateKey_file(tlsctx, key_file_path, SSL_FILETYPE_PEM);
    (void)result;
  }

  void setupTLS(const char *server_name)
  {
    TLSBase::setupTLS(tlsctx, false);
    SSL_set_tlsext_host_name(ssl, server_name);
  }

  void createAndConfigureTCPSocket(int ipVersion, bool fastOpen, uint32_t keepaliveTimeoutSeconds)
  {
    setIPVersion(ipVersion);
    if (fastOpen)
    {
      enableTCPFastOpen();
    }
    if (keepaliveTimeoutSeconds > 0)
    {
      setKeepaliveTimeoutSeconds(keepaliveTimeoutSeconds);
    }
  }

  void setIPv4FromURI(const char *uri, uint16_t port)
  {
    if (domain != AF_INET)
    {
      setIPVersion(AF_INET);
    }
    setDaddrFromURI(uri, port);
  }

  void setIPv6FromURI(const char *uri, uint16_t port)
  {
    if (domain != AF_INET6)
    {
      setIPVersion(AF_INET6);
    }
    setDaddrFromURI(uri, port);
  }

  void finishSetup(const char *server_name)
  {
    setupTLS(server_name);
  }

  void socketFailed(void)
  {
    if (isFailed == false)
    {
      isFailed = true;
      connectionBroke();

      Ring::queueCancelAll(this);
      Ring::queueClose(this);
    }
  }

  void connectHandler(void *socket, int result)
  {
    if (result == 0)
    {
      sendTLSClientHello();
    }
    else
    {
      Ring::queueClose(this);
    }
  }

  void recvHandler(void *socket, int result)
  {
    pendingRecv = false;

    if (result <= 0 || recv(result) == false)
    {
      socketFailed();
    }
  }

  void sendHandler(void *socket, int result)
  {
    pendingSend = false;
    pendingSendBytes = 0;

    if (result > 0)
    {
      wBuffer.consume(result, true);
      wBuffer.noteSendCompleted();
      nEncryptedBytesToSend -= result;

      if (nEncryptedBytesToSend > 0)
      {
        Ring::queueSend(this);
      }
      else if (wBuffer.outstandingBytes() > 0) // more unencrypted bytes to send
      {
        send(isTLSNegotiated());
      }
    }
    else
    {
      wBuffer.noteSendCompleted();
      socketFailed();
    }
  }

  void closeHandler(void *socket)
  {
    isFailed = false;
    recreateSocket();
    Ring::installFDIntoFixedFileSlot(this);
    Ring::queueConnect(this);
  }

  H2NonBlockingClient()
      : tlsctx(getHTTP2TLSCtx()),
        credentials(100U, MemoryType::heap),
        authority(100U, MemoryType::heap)
  {
    rBuffer.reserve(256_KB);
    wBuffer.reserve(64_KB);
  }

  ~H2NonBlockingClient()
  {
    clearPendingRequests(false);
    completedTickets.clear();

    if (session)
    {
      nghttp2_session_del(session);
      session = nullptr;
    }

    TLSBase::destroyTLS();

    if (tlsctx)
    {
      SSL_CTX_free(tlsctx);
      tlsctx = nullptr;
    }
  }
};

// we could be multiplexing multiple coroutines over the same HTTP2Client
// so that's why it makes sense to also have this where its one single logical flow
class SuspendableHTTP2Client : public H2NonBlockingClient, public CoroutineStack {
public:

  Ticket ticket;

  void connected(void)
  {
    // are we suspended? wakeup
    if (hasSuspendedCoroutines())
    {
      co_consume();
    }
  }

  SuspendableHTTP2Client()
      : ticket(this)
  {}
};

using HTTP2Client = H2NonBlockingClient;
