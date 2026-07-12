// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/async.dns.cares.h>
#include <networking/multi.curl.client.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <zlib.h>

namespace
{

static bool ringSupported(void)
{
   const pid_t child = fork();
   if (child == 0)
   {
      Ring::interfacer = nullptr;
      Ring::lifecycler = nullptr;
      Ring::exit = false;
      Ring::shuttingDown = false;
      Ring::createRing(32, 64, 4, 2, -1, -1, 4);
      Ring::shutdownForExec();
      _exit(0);
   }
   if (child < 0)
   {
      return false;
   }
   int status = 0;
   return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void append16(Vector<uint8_t>& bytes, uint16_t value)
{
   bytes.push_back(uint8_t(value >> 8));
   bytes.push_back(uint8_t(value));
}

static void append32(Vector<uint8_t>& bytes, uint32_t value)
{
   bytes.push_back(uint8_t(value >> 24));
   bytes.push_back(uint8_t(value >> 16));
   bytes.push_back(uint8_t(value >> 8));
   bytes.push_back(uint8_t(value));
}

static String gzip(const String& input)
{
   z_stream stream = {};
   if (deflateInit2(&stream,
                    Z_BEST_COMPRESSION,
                    Z_DEFLATED,
                    MAX_WBITS + 16,
                    8,
                    Z_DEFAULT_STRATEGY) != Z_OK)
   {
      return {};
   }
   Vector<uint8_t> output;
   output.resize(size_t(input.size() + 128));
   stream.next_in = reinterpret_cast<Bytef *>(input.data());
   stream.avail_in = uInt(input.size());
   stream.next_out = output.data();
   stream.avail_out = uInt(output.size());
   const int status = deflate(&stream, Z_FINISH);
   String compressed;
   if (status == Z_STREAM_END)
   {
      compressed.assign(output.data(), stream.total_out);
   }
   deflateEnd(&stream);
   return compressed;
}

class DnsFixture
{
private:

   int fd = -1;
   uint16_t boundPort = 0;
   std::atomic<bool> stopping = false;
   std::atomic<uint32_t> queries = 0;
   uint32_t delayMilliseconds = 0;
   bool answerIpv6 = false;
   std::thread worker;

   void run(void)
   {
      while (!stopping.load(std::memory_order_relaxed))
      {
         pollfd descriptor {.fd = fd, .events = POLLIN, .revents = 0};
         if (poll(&descriptor, 1, 25) <= 0)
         {
            continue;
         }
         uint8_t query[512] = {};
         sockaddr_storage peer = {};
         socklen_t peerLength = sizeof(peer);
         const ssize_t size = recvfrom(fd,
                                       query,
                                       sizeof(query),
                                       0,
                                       reinterpret_cast<sockaddr *>(&peer),
                                       &peerLength);
         if (size < 17)
         {
            continue;
         }
         const size_t queryBytes = size_t(size);
         size_t offset = 12;
         while (offset < queryBytes && query[offset] != 0)
         {
            const size_t label = query[offset++];
            if (label > 63 || offset + label > queryBytes)
            {
               offset = queryBytes;
               break;
            }
            offset += label;
         }
         if (++offset + 4 > queryBytes)
         {
            continue;
         }
         const uint16_t type = uint16_t(query[offset] << 8 | query[offset + 1]);
         const size_t questionEnd = offset + 4;
         const bool ipv4 = type == 1;
         const bool ipv6 = type == 28 && answerIpv6;
         Vector<uint8_t> response;
         response.insert(response.end(), query, query + 2);
         append16(response, 0x8180);
         append16(response, 1);
         append16(response, ipv4 || ipv6 ? 1 : 0);
         append16(response, 0);
         append16(response, 0);
         response.insert(response.end(), query + 12, query + questionEnd);
         if (ipv4)
         {
            append16(response, 0xC00C);
            append16(response, 1);
            append16(response, 1);
            append32(response, 1);
            append16(response, 4);
            response.push_back(127);
            response.push_back(0);
            response.push_back(0);
            response.push_back(1);
         }
         else if (ipv6)
         {
            append16(response, 0xC00C);
            append16(response, 28);
            append16(response, 1);
            append32(response, 1);
            append16(response, 16);
            for (size_t index = 0; index < 15; ++index)
            {
               response.push_back(0);
            }
            response.push_back(1);
         }
         if (delayMilliseconds != 0)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMilliseconds));
         }
         (void)sendto(fd,
                      response.data(),
                      response.size(),
                      0,
                      reinterpret_cast<sockaddr *>(&peer),
                      peerLength);
         queries.fetch_add(1, std::memory_order_relaxed);
      }
   }

public:

   explicit DnsFixture(uint32_t delay = 0, bool ipv6 = false)
       : delayMilliseconds(delay),
         answerIpv6(ipv6)
   {
      fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0)
      {
         return;
      }
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
      {
         close(fd);
         fd = -1;
         return;
      }
      socklen_t length = sizeof(address);
      if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) != 0)
      {
         close(fd);
         fd = -1;
         return;
      }
      boundPort = ntohs(address.sin_port);
      worker = std::thread([this]
      {
         run();
      });
   }

   ~DnsFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (fd >= 0)
      {
         close(fd);
      }
      if (worker.joinable())
      {
         worker.join();
      }
   }

   bool ready(void) const
   {
      return fd >= 0 && boundPort != 0;
   }

   String servers(void) const
   {
      String value;
      value.snprintf<"127.0.0.1:{itoa}"_ctv>(uint64_t(boundPort));
      return value;
   }

   uint32_t queryCount(void) const
   {
      return queries.load(std::memory_order_relaxed);
   }
};

struct HttpResponse
{
   String informationalHeaders;
};

class HttpFixture
{
private:

   int listener = -1;
   uint16_t boundPort = 0;
   String body;
   String informationalHeaders;
   String expectedAuthority;
   String expectedMethod;
   String contentEncoding;
   uint32_t delayMilliseconds = 0;
   uint32_t expectedConnections = 1;
   std::atomic<bool> stopping = false;
   std::atomic<bool> authorityMatched = true;
   std::atomic<bool> methodMatched = true;
   std::thread worker;

   static bool sendAll(int fd, const String& response)
   {
      size_t sent = 0;
      while (sent < response.size())
      {
         const ssize_t count = send(fd,
                                    response.data() + sent,
                                    response.size() - sent,
                                    MSG_NOSIGNAL);
         if (count <= 0)
         {
            return false;
         }
         sent += size_t(count);
      }
      return true;
   }

   void start(int family = AF_INET)
   {
      listener = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (listener < 0)
      {
         return;
      }
      const int enabled = 1;
      (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
      sockaddr_storage storage = {};
      socklen_t length = 0;
      if (family == AF_INET6)
      {
         sockaddr_in6 address = {};
         address.sin6_family = AF_INET6;
         address.sin6_addr = in6addr_loopback;
         std::memcpy(&storage, &address, sizeof(address));
         length = sizeof(address);
      }
      else
      {
         sockaddr_in address = {};
         address.sin_family = AF_INET;
         address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
         std::memcpy(&storage, &address, sizeof(address));
         length = sizeof(address);
      }
      if (bind(listener, reinterpret_cast<sockaddr *>(&storage), length) != 0 ||
          listen(listener, 8) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      if (getsockname(listener, reinterpret_cast<sockaddr *>(&storage), &length) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      boundPort = family == AF_INET6
                      ? ntohs(reinterpret_cast<sockaddr_in6 *>(&storage)->sin6_port)
                      : ntohs(reinterpret_cast<sockaddr_in *>(&storage)->sin_port);
      worker = std::thread([this]
      {
         run();
      });
   }

   void run(void)
   {
      uint32_t completed = 0;
      while (!stopping.load(std::memory_order_relaxed))
      {
         pollfd descriptor {.fd = listener, .events = POLLIN, .revents = 0};
         if (poll(&descriptor, 1, 25) <= 0)
         {
            continue;
         }
         const int connection = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
         if (connection < 0)
         {
            continue;
         }
         char request[4096] = {};
         (void)recv(connection, request, sizeof(request) - 1, 0);
         if (!expectedAuthority.empty() && std::strstr(request, expectedAuthority.c_str()) == nullptr)
         {
            authorityMatched.store(false, std::memory_order_relaxed);
         }
         if (!expectedMethod.empty() &&
             std::strncmp(request, expectedMethod.c_str(), expectedMethod.size()) != 0)
         {
            methodMatched.store(false, std::memory_order_relaxed);
         }
         if (delayMilliseconds != 0 && completed == 0)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMilliseconds));
         }
         if (!informationalHeaders.empty())
         {
            String informational;
            informational.assign("HTTP/1.1 100 Continue\r\n"_ctv);
            informational.append(informationalHeaders);
            informational.append("\r\n"_ctv);
            (void)sendAll(connection, informational);
            (void)recv(connection, request, sizeof(request), 0);
         }
         String response;
         response.snprintf<"HTTP/1.1 200 OK\r\nContent-Length: {itoa}\r\n"_ctv>(uint64_t(body.size()));
         if (!contentEncoding.empty())
         {
            response.append("Content-Encoding: "_ctv);
            response.append(contentEncoding);
            response.append("\r\n"_ctv);
         }
         response.append("Connection: close\r\n\r\n"_ctv);
         response.append(body);
         (void)sendAll(connection, response);
         close(connection);
         if (++completed == expectedConnections)
         {
            return;
         }
      }
   }

public:

   HttpFixture(const String& responseBody,
               uint32_t delay,
               uint32_t connections = 1,
               const char *requiredAuthority = nullptr,
               const char *encoding = nullptr,
               const char *requiredMethod = nullptr,
               int listenFamily = AF_INET)
       : body(responseBody),
         expectedAuthority(requiredAuthority ? requiredAuthority : ""),
         expectedMethod(requiredMethod ? requiredMethod : ""),
         contentEncoding(encoding ? encoding : ""),
         delayMilliseconds(delay),
         expectedConnections(connections)
   {
      start(listenFamily);
   }

   explicit HttpFixture(HttpResponse response)
       : informationalHeaders(std::move(response.informationalHeaders))
   {
      start();
   }

   ~HttpFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (listener >= 0)
      {
         shutdown(listener, SHUT_RDWR);
         close(listener);
      }
      if (worker.joinable())
      {
         worker.join();
      }
   }

   bool ready(void) const
   {
      return listener >= 0 && boundPort != 0;
   }

   String url(void) const
   {
      String value;
      value.snprintf<"http://127.0.0.1:{itoa}/"_ctv>(uint64_t(boundPort));
      return value;
   }

   uint16_t port(void) const
   {
      return boundPort;
   }

   bool sawExpectedAuthority(void) const
   {
      return authorityMatched.load(std::memory_order_relaxed);
   }

   bool sawExpectedMethod(void) const
   {
      return methodMatched.load(std::memory_order_relaxed);
   }

};

class SequenceDnsClient final : public AsyncDnsClient
{
public:

   struct Answer
   {
      Vector<String> addresses;
      uint32_t ttlSeconds = 0;
   };

private:

   Vector<Answer> answers;
   uint64_t nextTicket = 1;
   size_t calls = 0;

public:

   explicit SequenceDnsClient(Vector<Answer> configured)
       : answers(std::move(configured))
   {}

   SequenceDnsClient(std::initializer_list<Answer> configured)
   {
      for (const Answer& answer : configured)
      {
         answers.push_back(answer);
      }
   }

   static Answer makeAnswer(std::initializer_list<const char *> values, uint32_t ttlSeconds)
   {
      Answer answer;
      answer.ttlSeconds = ttlSeconds;
      for (const char *value : values)
      {
         answer.addresses.push_back(String(value));
      }
      return answer;
   }

   bool ready(void) const override
   {
      return true;
   }

   Ticket resolve(const String&,
                  const String& service,
                  Family,
                  Callback callback,
                  TimePoint = TimePoint::max()) override
   {
      Ticket ticket {nextTicket++, 1};
      Answer& answer = answers[std::min(calls, answers.size() - 1)];
      ++calls;
      Resolver::Result result;
      result.status = Resolver::Status::success;
      String serviceCopy = service;
      const uint16_t port = uint16_t(std::strtoul(serviceCopy.c_str(), nullptr, 10));
      for (String& value : answer.addresses)
      {
         Resolver::Address address;
         address.ttlSeconds = answer.ttlSeconds;
         sockaddr_in ipv4 = {};
         sockaddr_in6 ipv6 = {};
         if (inet_pton(AF_INET, value.c_str(), &ipv4.sin_addr) == 1)
         {
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = htons(port);
            std::memcpy(&address.storage, &ipv4, sizeof(ipv4));
            address.length = sizeof(ipv4);
         }
         else
         {
            ipv6.sin6_family = AF_INET6;
            ipv6.sin6_port = htons(port);
            (void)inet_pton(AF_INET6, value.c_str(), &ipv6.sin6_addr);
            std::memcpy(&address.storage, &ipv6, sizeof(ipv6));
            address.length = sizeof(ipv6);
         }
         result.addresses.push_back(address);
      }
      callback.function(callback.context, ticket, std::move(result));
      return ticket;
   }

   bool cancel(Ticket) override
   {
      return false;
   }

   size_t resolveCount(void) const
   {
      return calls;
   }
};

class NumericDnsClient final : public AsyncDnsClient
{
private:

   AsyncDnsResolver resolver;

public:

   bool ready(void) const override
   {
      return !resolver.isShutdown();
   }

   Ticket resolve(const String& hostname,
                  const String& service,
                  Family family,
                  Callback callback,
                  TimePoint deadline = TimePoint::max()) override
   {
      return resolver.resolve(hostname, service, family, callback, deadline);
   }

   bool cancel(Ticket ticket) override
   {
      return resolver.cancel(ticket);
   }
};

struct CurlBatchScenario final : RingMultiplexer
{
   MultiCurlClient *client = nullptr;
   TimeoutPacket guard;
   Vector<MultiCurlClient::Result> results;
   size_t expected = 0;
   bool guardArmed = false;
   bool timedOut = false;

   CurlBatchScenario()
   {
      guard.originator = this;
   }

   static void callback(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& result)
   {
      CurlBatchScenario& scenario = *static_cast<CurlBatchScenario *>(context);
      scenario.results.push_back(std::move(result));
      if (scenario.results.size() == scenario.expected)
      {
         (void)scenario.client->shutdown();
         if (scenario.guardArmed)
         {
            Ring::queueCancelTimeout(&scenario.guard);
         }
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (result != -ECANCELED)
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

static Vector<MultiCurlClient::Result> runCurlBatch(TestSuite& suite,
                                                     AsyncDnsClient& resolver,
                                                     MultiCurlClient::Config config,
                                                     Vector<MultiCurlClient::Request> requests)
{
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);

   CurlBatchScenario scenario;
   scenario.expected = requests.size();
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   scenario.client = new MultiCurlClient(resolver, std::move(config));
   EXPECT_TRUE(suite, scenario.client->ready());
   scenario.guard.setTimeoutSeconds(8);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   for (MultiCurlClient::Request& request : requests)
   {
      scenario.client->submit(std::move(request), {&scenario, CurlBatchScenario::callback});
   }
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_EQ(suite, scenario.results.size(), scenario.expected);
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   return std::move(scenario.results);
}

struct Scenario final : RingMultiplexer
{
   TestSuite *suite = nullptr;
   MultiCurlClient *client = nullptr;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool guardCancellationRequested = false;
   bool fastDone = false;
   bool slowDone = false;
   bool canceledDone = false;
   bool invalidHeaderDone = false;
   bool invalidAuthorityDone = false;
   bool capDone = false;
   bool compressedCapDone = false;
   bool compressedCapStatusCorrect = false;
   bool deadlineDone = false;
   bool clearedLocationDone = false;
   bool duplicateLocationDone = false;
   bool timedOut = false;
   bool firstCompletedWhileSecondActive = false;
   uint32_t fastCalls = 0;
   uint32_t slowCalls = 0;
   uint32_t canceledCalls = 0;
   uint32_t invalidHeaderCalls = 0;
   uint32_t invalidAuthorityCalls = 0;
   uint32_t capCalls = 0;
   uint32_t compressedCapCalls = 0;
   uint32_t deadlineCalls = 0;

   explicit Scenario(TestSuite& testSuite)
       : suite(&testSuite)
   {
      guard.originator = this;
   }

   static void fastCallback(void *context,
                            MultiCurlClient::Ticket,
                            MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.fastCalls;
      scenario.fastDone = result.succeeded() && result.statusCode == 200 && result.body == "fast"_ctv;
      scenario.firstCompletedWhileSecondActive = scenario.client->activeTransferCount() > 0;
      scenario.beginShutdownIfDone();
   }

   static void slowCallback(void *context,
                            MultiCurlClient::Ticket,
                            MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.slowCalls;
      scenario.slowDone = result.succeeded() && result.statusCode == 200 && result.body == "slow"_ctv;
      scenario.beginShutdownIfDone();
   }

   static void canceledCallback(void *context,
                                MultiCurlClient::Ticket,
                                MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.canceledCalls;
      scenario.canceledDone = result.status == MultiCurlClient::Status::canceled;
      scenario.beginShutdownIfDone();
   }

   static void invalidHeaderCallback(void *context,
                                     MultiCurlClient::Ticket,
                                     MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.invalidHeaderCalls;
      scenario.invalidHeaderDone = result.status == MultiCurlClient::Status::invalidRequest;
      scenario.beginShutdownIfDone();
   }

   static void invalidAuthorityCallback(void *context,
                                        MultiCurlClient::Ticket,
                                        MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.invalidAuthorityCalls;
      scenario.invalidAuthorityDone = result.status == MultiCurlClient::Status::invalidRequest;
      scenario.beginShutdownIfDone();
   }

   static void capCallback(void *context,
                           MultiCurlClient::Ticket,
                           MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.capCalls;
      scenario.capDone = result.status == MultiCurlClient::Status::responseTooLarge;
      scenario.beginShutdownIfDone();
   }

   static void compressedCapCallback(void *context,
                                     MultiCurlClient::Ticket,
                                     MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.compressedCapCalls;
      scenario.compressedCapDone = true;
      scenario.compressedCapStatusCorrect =
          result.status == MultiCurlClient::Status::responseTooLarge;
      scenario.beginShutdownIfDone();
   }

   static void deadlineCallback(void *context,
                                MultiCurlClient::Ticket,
                                MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.deadlineCalls;
      scenario.deadlineDone = result.status == MultiCurlClient::Status::deadlineExceeded;
      scenario.beginShutdownIfDone();
   }

   static void clearedLocationCallback(void *context,
                                       MultiCurlClient::Ticket,
                                       MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      EXPECT_EQ(*scenario.suite,
                int(result.status),
                int(MultiCurlClient::Status::success));
      EXPECT_EQ(*scenario.suite, int(result.curlCode), int(CURLE_OK));
      EXPECT_EQ(*scenario.suite, result.statusCode, 200L);
      EXPECT_TRUE(*scenario.suite, result.location.empty());
      scenario.clearedLocationDone = true;
      scenario.beginShutdownIfDone();
   }

   static void duplicateLocationCallback(void *context,
                                         MultiCurlClient::Ticket,
                                         MultiCurlClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      EXPECT_EQ(*scenario.suite,
                int(result.status),
                int(MultiCurlClient::Status::invalidResponse));
      scenario.duplicateLocationDone = true;
      scenario.beginShutdownIfDone();
   }

   void beginShutdownIfDone(void)
   {
      if (!fastDone || !slowDone || !canceledDone || !invalidHeaderDone || !invalidAuthorityDone ||
          !capDone || !compressedCapDone || !deadlineDone || !clearedLocationDone ||
          !duplicateLocationDone)
      {
         return;
      }
      (void)client->shutdown();
      if (guardArmed && !guardCancellationRequested)
      {
         guardCancellationRequested = true;
         Ring::queueCancelTimeout(&guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guardCancellationRequested = false;
      guard.clear();
      if (result != -ECANCELED)
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
      if (client && client->shutdownSafe() && !guardArmed)
      {
         Ring::exit = true;
      }
   }
};

static MultiCurlClient::Request requestFor(const HttpFixture& fixture)
{
   MultiCurlClient::Request request;
   request.url = fixture.url();
   request.requireTls = false;
   request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
   request.responseBytes = 1024;
   request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);
   return request;
}

static MultiCurlClient::Request continueRequestFor(const HttpFixture& fixture)
{
   MultiCurlClient::Request request = requestFor(fixture);
   request.method = MultiCurlClient::Method::post;
   request.headers.push_back({"Expect", "100-continue"});
   request.body.assign("x"_ctv);
   return request;
}

static MultiCurlClient::Request plainRequest(const String& host, uint16_t port)
{
   MultiCurlClient::Request request;
   request.url.assign("http://"_ctv);
   request.url.append(host);
   String service;
   service.snprintf<":{itoa}/"_ctv>(uint64_t(port));
   request.url.append(service);
   request.requireTls = false;
   request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
   request.responseBytes = 1024;
   request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(5);
   return request;
}

static void testZeroTtlImmediateAndQueuedAdmission(TestSuite& suite)
{
   HttpFixture available("zero", 0);
   EXPECT_TRUE(suite, available.ready());
   SequenceDnsClient immediate({SequenceDnsClient::makeAnswer({"127.0.0.1"}, 0)});
   Vector<MultiCurlClient::Request> immediateRequests;
   immediateRequests.push_back(plainRequest("zero.test", available.port()));
   Vector<MultiCurlClient::Result> immediateResults =
       runCurlBatch(suite, immediate, {}, std::move(immediateRequests));
   EXPECT_EQ(suite, immediate.resolveCount(), size_t(1));
   EXPECT_EQ(suite, immediateResults.size(), size_t(1));
   if (!immediateResults.empty())
   {
      EXPECT_TRUE(suite, immediateResults[0].succeeded());
      EXPECT_EQ(suite, immediateResults[0].resolvedTtlSeconds, uint32_t(0));
   }

   HttpFixture queued("queued", 400, 2);
   EXPECT_TRUE(suite, queued.ready());
   SequenceDnsClient queuedDns({SequenceDnsClient::makeAnswer({"127.0.0.1"}, 0),
                                SequenceDnsClient::makeAnswer({"127.0.0.2"}, 0),
                                SequenceDnsClient::makeAnswer({"127.0.0.1"}, 0)});
   MultiCurlClient::Config config;
   config.totalConnections = 1;
   config.hostConnections = 1;
   Vector<MultiCurlClient::Request> queuedRequests;
   queuedRequests.push_back(plainRequest("queued.test", queued.port()));
   queuedRequests.push_back(plainRequest("queued.test", queued.port()));
   Vector<MultiCurlClient::Result> queuedResults =
       runCurlBatch(suite, queuedDns, config, std::move(queuedRequests));
   EXPECT_EQ(suite, queuedDns.resolveCount(), size_t(3));
   EXPECT_EQ(suite, queuedResults.size(), size_t(2));
   for (const MultiCurlClient::Result& result : queuedResults)
   {
      EXPECT_TRUE(suite, result.succeeded());
      EXPECT_EQ(suite, result.resolvedTtlSeconds, uint32_t(0));
   }
}

static void testRealHappyEyeballsFamilyFallback(TestSuite& suite)
{
   HttpFixture ipv4Only("fallback", 0);
   EXPECT_TRUE(suite, ipv4Only.ready());
   SequenceDnsClient resolver({SequenceDnsClient::makeAnswer({"::1", "127.0.0.1"}, 30)});
   Vector<MultiCurlClient::Request> requests;
   requests.push_back(plainRequest("dual.test", ipv4Only.port()));
   Vector<MultiCurlClient::Result> results = runCurlBatch(suite, resolver, {}, std::move(requests));
   EXPECT_EQ(suite, resolver.resolveCount(), size_t(1));
   EXPECT_EQ(suite, results.size(), size_t(1));
   if (!results.empty())
   {
      EXPECT_TRUE(suite, results[0].succeeded());
      EXPECT_TRUE(suite, results[0].body == "fallback"_ctv);
   }
}

struct LiteralPolicyCapture
{
   String host;
   String authority;
   String connectHost;
   size_t calls = 0;

   static bool origin(void *context,
                      const String&,
                      const String& host,
                      const String& authority,
                      const String&,
                      const String& connectHost)
   {
      LiteralPolicyCapture& capture = *static_cast<LiteralPolicyCapture *>(context);
      capture.host = host;
      capture.authority = authority;
      capture.connectHost = connectHost;
      ++capture.calls;
      return true;
   }

   static bool rejectAddress(void *, const AsyncDnsResolver::Address&)
   {
      return false;
   }
};

static MultiCurlClient::Request literalRequest(const String& literal,
                                                uint16_t port,
                                                LiteralPolicyCapture& capture,
                                                bool rejectAddress)
{
   MultiCurlClient::Request request = plainRequest(literal, port);
   request.originPolicy.context = &capture;
   request.originPolicy.accept = LiteralPolicyCapture::origin;
   if (rejectAddress)
   {
      request.addressPolicy.accept = LiteralPolicyCapture::rejectAddress;
   }
   return request;
}

static void testIpv6LiteralCanonicalizationAndPolicy(TestSuite& suite)
{
   HttpFixture ipv6("literal", 0, 1, nullptr, nullptr, nullptr, AF_INET6);
   EXPECT_TRUE(suite, ipv6.ready());
   NumericDnsClient resolver;
   LiteralPolicyCapture generic;
   Vector<MultiCurlClient::Request> requests;
   requests.push_back(literalRequest("[::1]", ipv6.port(), generic, false));
   Vector<MultiCurlClient::Result> results = runCurlBatch(suite, resolver, {}, std::move(requests));
   EXPECT_EQ(suite, results.size(), size_t(1));
   if (!results.empty())
   {
      EXPECT_TRUE(suite, results[0].succeeded());
   }
   EXPECT_EQ(suite, generic.calls, size_t(1));
   EXPECT_TRUE(suite, generic.host == "::1"_ctv);
   EXPECT_TRUE(suite, generic.connectHost == "::1"_ctv);
   EXPECT_TRUE(suite, generic.authority == "[::1]"_ctv);

   LiteralPolicyCapture rejected;
   Vector<MultiCurlClient::Request> rejectedRequests;
   rejectedRequests.push_back(literalRequest("[::1]", ipv6.port(), rejected, true));
   rejectedRequests.push_back(literalRequest("[2001:db8::1]", 80, rejected, true));
   rejectedRequests.push_back(literalRequest("[2606:4700:4700::1111]", 80, rejected, true));
   Vector<MultiCurlClient::Result> rejectedResults =
       runCurlBatch(suite, resolver, {}, std::move(rejectedRequests));
   EXPECT_EQ(suite, rejectedResults.size(), size_t(3));
   for (const MultiCurlClient::Result& result : rejectedResults)
   {
      EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::addressRejected);
   }
   EXPECT_EQ(suite, rejected.calls, size_t(3));
   EXPECT_TRUE(suite, rejected.host == "2606:4700:4700::1111"_ctv);
   EXPECT_TRUE(suite, rejected.connectHost == "2606:4700:4700::1111"_ctv);

   LiteralPolicyCapture malformedCapture;
   Vector<MultiCurlClient::Request> malformed;
   malformed.push_back(literalRequest("[[::1]]", 80, malformedCapture, true));
   malformed.push_back(literalRequest("[::1]]", 80, malformedCapture, true));
   malformed.push_back(literalRequest("[[::1]", 80, malformedCapture, true));
   MultiCurlClient::Request override = literalRequest("[::1]", 80, malformedCapture, true);
   override.resolveHost = "::2";
   malformed.push_back(std::move(override));
   Vector<MultiCurlClient::Result> malformedResults =
       runCurlBatch(suite, resolver, {}, std::move(malformed));
   EXPECT_EQ(suite, malformedResults.size(), size_t(4));
   for (const MultiCurlClient::Result& result : malformedResults)
   {
      EXPECT_TRUE(suite, result.status == MultiCurlClient::Status::unsupportedProtocol);
   }
}

static void testConcurrentCompletionCancellationAndShutdown(TestSuite& suite)
{
   (void)setenv("HTTP_PROXY", "http://127.0.0.1:1", 1);
   (void)setenv("HTTPS_PROXY", "http://127.0.0.1:1", 1);
   (void)setenv("ALL_PROXY", "http://127.0.0.1:1", 1);
   HttpFixture fast("fast", 0, 1, nullptr, nullptr, "PATCH");
   HttpFixture slow("slow", 150);
   HttpFixture cancelFixture("cancel", 1000);
   HttpFixture capFixture("response exceeds cap", 0);
   String decompressedBody;
   decompressedBody.reserve(2048);
   decompressedBody.resize(2048);
   std::memset(decompressedBody.data(), 'x', decompressedBody.size());
   const String compressedBody = gzip(decompressedBody);
   HttpFixture compressedCapFixture(compressedBody, 0, 1, nullptr, "gzip");
   HttpFixture deadlineFixture("late", 400);
   HttpResponse clearedLocationResponse;
   clearedLocationResponse.informationalHeaders.assign("Location: /early\r\n"_ctv);
   for (size_t index = 1; index < MultiCurlClient::maximumRequestHeaders; ++index)
   {
      String header;
      header.snprintf<"X-{itoa}: value\r\n"_ctv>(uint64_t(index));
      clearedLocationResponse.informationalHeaders.append(header);
   }
   HttpFixture clearedLocationFixture(std::move(clearedLocationResponse));
   HttpResponse duplicateLocationResponse;
   duplicateLocationResponse.informationalHeaders.assign(
       "Location: /first\r\nLocation: /second\r\n"_ctv);
   HttpFixture duplicateLocationFixture(std::move(duplicateLocationResponse));
   EXPECT_TRUE(suite, fast.ready());
   EXPECT_TRUE(suite, slow.ready());
   EXPECT_TRUE(suite, cancelFixture.ready());
   EXPECT_TRUE(suite, capFixture.ready());
   EXPECT_TRUE(suite, compressedBody.size() < decompressedBody.size());
   EXPECT_TRUE(suite, compressedCapFixture.ready());
   EXPECT_TRUE(suite, deadlineFixture.ready());
   EXPECT_TRUE(suite, clearedLocationFixture.ready());
   EXPECT_TRUE(suite, duplicateLocationFixture.ready());
   if (!fast.ready() || !slow.ready() || !cancelFixture.ready() ||
       !capFixture.ready() || !compressedCapFixture.ready() || !deadlineFixture.ready() ||
       !clearedLocationFixture.ready() || !duplicateLocationFixture.ready())
   {
      (void)unsetenv("HTTP_PROXY");
      (void)unsetenv("HTTPS_PROXY");
      (void)unsetenv("ALL_PROXY");
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);

   Scenario scenario(suite);
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   RingAsyncDnsResolver resolver;
   scenario.client = new MultiCurlClient(resolver);
   EXPECT_TRUE(suite, scenario.client->ready());
   {
      MultiCurlClient duplicate(resolver);
      EXPECT_FALSE(suite, duplicate.ready());
      EXPECT_TRUE(suite,
                  duplicate.initializationStatus() ==
                     MultiCurlClient::InitializationStatus::threadClientAlreadyExists);
   }

   MultiCurlClient::Request invalid = requestFor(fast);
   invalid.headers.push_back({"Host", "invalid.test"});
   scenario.client->submit(std::move(invalid), {&scenario, Scenario::invalidHeaderCallback});
   MultiCurlClient::Request invalidAuthority = requestFor(fast);
   invalidAuthority.authority.assign("invalid\nauthority"_ctv);
   scenario.client->submit(std::move(invalidAuthority),
                           {&scenario, Scenario::invalidAuthorityCallback});

   MultiCurlClient::Request canceled = requestFor(cancelFixture);
   const auto canceledTicket = scenario.client->submit(std::move(canceled),
                                                        {&scenario, Scenario::canceledCallback});
   EXPECT_TRUE(suite, scenario.client->cancel(canceledTicket));

   scenario.client->submit(requestFor(slow), {&scenario, Scenario::slowCallback});
   MultiCurlClient::Request patch = requestFor(fast);
   patch.method = MultiCurlClient::Method::patch;
   scenario.client->submit(std::move(patch), {&scenario, Scenario::fastCallback});
   MultiCurlClient::Request capped = requestFor(capFixture);
   capped.responseBytes = 4;
   scenario.client->submit(std::move(capped), {&scenario, Scenario::capCallback});
   MultiCurlClient::Request compressedCapped = requestFor(compressedCapFixture);
   compressedCapped.responseBytes = 1024;
   scenario.client->submit(std::move(compressedCapped),
                           {&scenario, Scenario::compressedCapCallback});
   MultiCurlClient::Request deadline = requestFor(deadlineFixture);
   deadline.firstByteTimeout = std::chrono::milliseconds(50);
   scenario.client->submit(std::move(deadline), {&scenario, Scenario::deadlineCallback});
   scenario.client->submit(continueRequestFor(clearedLocationFixture),
                           {&scenario, Scenario::clearedLocationCallback});
   scenario.client->submit(continueRequestFor(duplicateLocationFixture),
                           {&scenario, Scenario::duplicateLocationCallback});
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.fastDone);
   EXPECT_TRUE(suite, scenario.slowDone);
   EXPECT_TRUE(suite, scenario.canceledDone);
   EXPECT_TRUE(suite, scenario.invalidHeaderDone);
   EXPECT_TRUE(suite, scenario.invalidAuthorityDone);
   EXPECT_TRUE(suite, scenario.capDone);
   EXPECT_TRUE(suite, scenario.compressedCapDone);
   EXPECT_TRUE(suite, scenario.compressedCapStatusCorrect);
   EXPECT_TRUE(suite, scenario.deadlineDone);
   EXPECT_TRUE(suite, scenario.clearedLocationDone);
   EXPECT_TRUE(suite, scenario.duplicateLocationDone);
   EXPECT_TRUE(suite, scenario.firstCompletedWhileSecondActive);
   EXPECT_TRUE(suite, fast.sawExpectedMethod());
   EXPECT_EQ(suite, scenario.fastCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.slowCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.canceledCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.invalidHeaderCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.invalidAuthorityCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.capCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.compressedCapCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.deadlineCalls, uint32_t(1));
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   scenario.client = nullptr;
   (void)resolver.shutdown();
   EXPECT_TRUE(suite, resolver.shutdownSafe());
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   (void)unsetenv("HTTP_PROXY");
   (void)unsetenv("HTTPS_PROXY");
   (void)unsetenv("ALL_PROXY");
}

struct ResetScenario final : RingMultiplexer
{
   MultiCurlClient *client = nullptr;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool completionDone = false;
   bool stateCorrect = false;
   bool resetMode = true;
   bool timedOut = false;
   uint32_t calls = 0;

   ResetScenario()
   {
      guard.originator = this;
   }

   static void callback(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& result)
   {
      ResetScenario& scenario = *static_cast<ResetScenario *>(context);
      ++scenario.calls;
      scenario.completionDone = result.status == (scenario.resetMode
                                                       ? MultiCurlClient::Status::reset
                                                       : MultiCurlClient::Status::shutdown);
      scenario.stateCorrect = scenario.resetMode ? scenario.client->ready()
                                                 : !scenario.client->ready();
      if (scenario.resetMode)
      {
         (void)scenario.client->shutdown();
      }
      if (scenario.guardArmed)
      {
         Ring::queueCancelTimeout(&scenario.guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (result != -ECANCELED)
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

static void testResetAndActiveShutdownBarriers(TestSuite& suite, bool resetMode)
{
   HttpFixture delayed("unused", 500);
   EXPECT_TRUE(suite, delayed.ready());
   if (!delayed.ready())
   {
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(64, 128, 4, 2, -1, -1, 4);

   ResetScenario scenario;
   scenario.resetMode = resetMode;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   RingAsyncDnsResolver resolver;
   scenario.client = new MultiCurlClient(resolver);
   EXPECT_TRUE(suite, scenario.client->ready());
   scenario.client->submit(requestFor(delayed), {&scenario, ResetScenario::callback});
   if (resetMode)
   {
      EXPECT_TRUE(suite, scenario.client->reset());
   }
   else
   {
      (void)scenario.client->shutdown();
   }
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.completionDone);
   EXPECT_TRUE(suite, scenario.stateCorrect);
   EXPECT_EQ(suite, scenario.calls, uint32_t(1));
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   (void)resolver.shutdown();
   EXPECT_TRUE(suite, resolver.shutdownSafe());
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
}

struct PinRefreshScenario final : RingMultiplexer
{
   MultiCurlClient *client = nullptr;
   TimeoutPacket guard;
   TimeoutPacket heartbeat;
   bool guardArmed = false;
   bool heartbeatArmed = false;
   bool timedOut = false;
   bool allSucceeded = true;
   uint32_t calls = 0;
   uint32_t heartbeats = 0;

   PinRefreshScenario()
   {
      guard.originator = this;
      heartbeat.originator = this;
   }

   static void callback(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& result)
   {
      PinRefreshScenario& scenario = *static_cast<PinRefreshScenario *>(context);
      ++scenario.calls;
      scenario.allSucceeded = scenario.allSucceeded && result.succeeded() &&
                              result.statusCode == 200 && result.body == "pin"_ctv;
      if (scenario.calls == 2)
      {
         (void)scenario.client->shutdown();
         if (scenario.guardArmed)
         {
            Ring::queueCancelTimeout(&scenario.guard);
         }
         if (scenario.heartbeatArmed)
         {
            Ring::queueCancelTimeout(&scenario.heartbeat);
         }
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet == &heartbeat)
      {
         heartbeatArmed = false;
         heartbeat.clear();
         if (result != -ECANCELED && calls < 2)
         {
            ++heartbeats;
            heartbeat.setTimeoutMs(10);
            heartbeatArmed = true;
            Ring::queueTimeout(&heartbeat);
         }
         if (client->shutdownSafe() && !guardArmed && !heartbeatArmed)
         {
            Ring::exit = true;
         }
         return;
      }
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (result != -ECANCELED)
      {
         timedOut = true;
         (void)client->shutdown();
      }
      if (client->shutdownSafe() && !heartbeatArmed)
      {
         Ring::exit = true;
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (client->shutdownSafe() && !guardArmed && !heartbeatArmed)
      {
         Ring::exit = true;
      }
   }
};

static void testQueuedPinExpiryReresolves(TestSuite& suite)
{
   DnsFixture dns(100);
   HttpFixture http("pin", 1200, 2);
   EXPECT_TRUE(suite, dns.ready());
   EXPECT_TRUE(suite, http.ready());
   if (!dns.ready() || !http.ready())
   {
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);

   PinRefreshScenario scenario;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   MultiCurlClient::Config config;
   config.totalConnections = 1;
   config.hostConnections = 1;
   RingAsyncDnsResolver::BackendConfig dnsConfig;
   dnsConfig.servers = dns.servers();
   RingAsyncDnsResolver resolver({}, std::move(dnsConfig));
   scenario.client = new MultiCurlClient(resolver, std::move(config));
   EXPECT_TRUE(suite, scenario.client->ready());

   MultiCurlClient::Request request;
   request.url.snprintf<"http://queue.test:{itoa}/"_ctv>(uint64_t(http.port()));
   request.requireTls = false;
   request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
   request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(5);
   request.firstByteTimeout = std::chrono::seconds(3);
   scenario.client->submit(request, {&scenario, PinRefreshScenario::callback});
   scenario.client->submit(std::move(request), {&scenario, PinRefreshScenario::callback});
   scenario.guard.setTimeoutSeconds(7);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   scenario.heartbeat.setTimeoutMs(10);
   scenario.heartbeatArmed = true;
   Ring::queueTimeout(&scenario.heartbeat);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.allSucceeded);
   EXPECT_EQ(suite, scenario.calls, uint32_t(2));
   EXPECT_TRUE(suite, scenario.heartbeats >= 5);
   EXPECT_TRUE(suite, dns.queryCount() >= 4);
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   (void)resolver.shutdown();
   EXPECT_TRUE(suite, resolver.shutdownSafe());
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
}

struct ReservedSourcePorts
{
   uint16_t first = 0;
   uint16_t second = 0;
};

static ReservedSourcePorts reserveLoopbackSourcePorts(void)
{
   int descriptors[2] = {socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0),
                         socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
   ReservedSourcePorts result;
   uint16_t *ports[2] = {&result.first, &result.second};
   for (size_t index = 0; index < 2 && descriptors[index] >= 0; ++index)
   {
      const int enabled = 1;
      (void)setsockopt(descriptors[index], SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      socklen_t length = sizeof(address);
      if (bind(descriptors[index], reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 &&
          getsockname(descriptors[index], reinterpret_cast<sockaddr *>(&address), &length) == 0)
      {
         *ports[index] = ntohs(address.sin_port);
      }
   }
   for (int fd : descriptors)
   {
      if (fd >= 0)
      {
         close(fd);
      }
   }
   return result;
}

struct LocalBindsScenario final : RingMultiplexer
{
   MultiCurlClient *client = nullptr;
   MultiCurlClient::Request secondRequest;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool guardCancellationRequested = false;
   bool timedOut = false;
   bool allSucceeded = true;
   uint32_t calls = 0;
   MultiCurlClient::Status lastStatus = MultiCurlClient::Status::success;
   CURLcode lastCurlCode = CURLE_OK;

   LocalBindsScenario()
   {
      guard.originator = this;
   }

   static void callback(void *context,
                        MultiCurlClient::Ticket,
                        MultiCurlClient::Result&& result)
   {
      LocalBindsScenario& scenario = *static_cast<LocalBindsScenario *>(context);
      ++scenario.calls;
      scenario.lastStatus = result.status;
      scenario.lastCurlCode = result.curlCode;
      scenario.allSucceeded = scenario.allSucceeded && result.succeeded() &&
                              result.statusCode == 200 && result.body == "bound"_ctv;
      if (scenario.calls == 1)
      {
         scenario.client->submit(std::move(scenario.secondRequest), {&scenario, callback});
         return;
      }

      (void)scenario.client->shutdown();
      if (scenario.guardArmed && !scenario.guardCancellationRequested)
      {
         scenario.guardCancellationRequested = true;
         Ring::queueCancelTimeout(&scenario.guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guardCancellationRequested = false;
      guard.clear();
      if (result != -ECANCELED)
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

static void testStructuredAuthorityAndReusableLocalBinds(TestSuite& suite)
{
   DnsFixture dns(0, true);
   HttpFixture fixture("bound", 0, 2, "Host: service.example\r\n");
   const ReservedSourcePorts sourcePorts = reserveLoopbackSourcePorts();
   EXPECT_TRUE(suite, dns.ready());
   EXPECT_TRUE(suite, fixture.ready());
   EXPECT_TRUE(suite, sourcePorts.first != 0 && sourcePorts.second != 0 &&
                      sourcePorts.first != sourcePorts.second);
   if (!dns.ready() || !fixture.ready() || sourcePorts.first == 0 || sourcePorts.second == 0)
   {
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(64, 128, 4, 2, -1, -1, 4);

   LocalBindsScenario scenario;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   MultiCurlClient::Config config;
   config.totalConnections = 1;
   config.hostConnections = 1;
   sockaddr_in local = {};
   local.sin_family = AF_INET;
   local.sin_port = htons(sourcePorts.first);
   local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   EXPECT_TRUE(suite,
               config.localBinds.add(reinterpret_cast<const sockaddr *>(&local), sizeof(local)));
   local.sin_port = htons(sourcePorts.second);
   EXPECT_TRUE(suite,
               config.localBinds.add(reinterpret_cast<const sockaddr *>(&local), sizeof(local)));
   RingAsyncDnsResolver::BackendConfig dnsConfig;
   dnsConfig.servers = dns.servers();
   RingAsyncDnsResolver resolver({}, std::move(dnsConfig));
   scenario.client = new MultiCurlClient(resolver, config);
   EXPECT_TRUE(suite, scenario.client->ready());

   MultiCurlClient::Request request;
   request.url.snprintf<"http://dual-bind.test:{itoa}/"_ctv>(uint64_t(fixture.port()));
   request.requireTls = false;
   request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
   request.responseBytes = 1024;
   request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);
   request.authority = "service.example";
   scenario.secondRequest = request;
   scenario.client->submit(std::move(request), {&scenario, LocalBindsScenario::callback});
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.allSucceeded);
   EXPECT_EQ(suite, int(scenario.lastStatus), int(MultiCurlClient::Status::success));
   EXPECT_EQ(suite, int(scenario.lastCurlCode), int(CURLE_OK));
   EXPECT_EQ(suite, scenario.calls, uint32_t(2));
   EXPECT_TRUE(suite, fixture.sawExpectedAuthority());
   EXPECT_TRUE(suite, dns.queryCount() >= 2 && dns.queryCount() % 2 == 0);
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   (void)resolver.shutdown();
   EXPECT_TRUE(suite, resolver.shutdownSafe());
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
}

} // namespace

int main()
{
   TestSuite suite;
   if (!ringSupported())
   {
      std::cout << "MultiCurlClient tests skipped: io_uring unavailable.\n";
      return suite.finish("MultiCurlClient");
   }
   testConcurrentCompletionCancellationAndShutdown(suite);
   testResetAndActiveShutdownBarriers(suite, true);
   testResetAndActiveShutdownBarriers(suite, false);
   testZeroTtlImmediateAndQueuedAdmission(suite);
   testIpv6LiteralCanonicalizationAndPolicy(suite);
   testRealHappyEyeballsFamilyFallback(suite);
   testQueuedPinExpiryReresolves(suite);
   testStructuredAuthorityAndReusableLocalBinds(suite);
   return suite.finish("MultiCurlClient");
}
