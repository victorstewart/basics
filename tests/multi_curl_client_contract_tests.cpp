// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/multi.curl.client.h>

static_assert(MultiCurlClient::maximumTransfers == 256);
static_assert(MultiCurlClient::maximumRequestHeaders == 32);
static_assert(MultiCurlClient::maximumHeaderBytes == 32 * 1024);
static_assert(MultiCurlClient::maximumResponseBytes == 16 * 1024 * 1024);
static_assert(MultiCurlClient::maximumSocketWatches == 1024);
static_assert(MultiCurlClient::maximumStagedSocketEvents == 4096);
static_assert(MultiCurlClient::maximumConcurrentStreams == 32);

int main()
{
   TestSuite suite;
   MultiCurlClient::Request request;
   request.url = "https://service.example/";
   request.resolveHost = "127.0.0.1";
   request.authority = "service.example";
   request.originPolicy.requiredScheme.assign("https"_ctv);
   request.originPolicy.requiredHost.assign("service.example"_ctv);
   request.originPolicy.requiredAuthority.assign("service.example"_ctv);
   request.originPolicy.requiredService.assign("443"_ctv);
   request.originPolicy.requiredResolveHost.assign("127.0.0.1"_ctv);
   request.headers.push_back({"Accept", "application/json"});
   EXPECT_TRUE(suite, request.headers.size() == 1);
   EXPECT_TRUE(suite, request.authority == "service.example"_ctv);
   EXPECT_TRUE(suite, request.originPolicy.accepts("https"_ctv,
                                                   "service.example"_ctv,
                                                   "service.example"_ctv,
                                                   "443"_ctv,
                                                   "127.0.0.1"_ctv));
   EXPECT_FALSE(suite, request.originPolicy.accepts("http"_ctv,
                                                    "service.example"_ctv,
                                                    "service.example"_ctv,
                                                    "443"_ctv,
                                                    "127.0.0.1"_ctv));
   EXPECT_TRUE(suite, request.httpPolicy == MultiCurlClient::HttpPolicy::preferHttp2);
   EXPECT_TRUE(suite, request.tlsMinimum == MultiCurlClient::TlsMinimum::tls12);

   sockaddr_in local4 = {};
   local4.sin_family = AF_INET;
   local4.sin_port = htons(43123);
   local4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   sockaddr_in6 local6 = {};
   local6.sin6_family = AF_INET6;
   local6.sin6_port = htons(43124);
   local6.sin6_addr = in6addr_loopback;
   MultiCurlClient::Config config;
   EXPECT_TRUE(suite,
               config.localBinds.add(reinterpret_cast<const sockaddr *>(&local4),
                                     sizeof(local4),
                                     true));
   EXPECT_TRUE(suite,
               config.localBinds.add(reinterpret_cast<const sockaddr *>(&local6), sizeof(local6)));
   const LocalSocketBindSet::Endpoint *bound4 = config.localBinds.at(AF_INET, 0);
   const LocalSocketBindSet::Endpoint *bound6 = config.localBinds.at(AF_INET6, 0);
   EXPECT_TRUE(suite, bound4 != nullptr && bound4->freebind);
   EXPECT_TRUE(suite, bound6 != nullptr && !bound6->freebind);
   EXPECT_TRUE(suite, config.localBinds.at(AF_UNSPEC, 0) == nullptr);
   EXPECT_TRUE(suite,
               !config.localBinds.add(reinterpret_cast<const sockaddr *>(&local4),
                                      sizeof(local4) - 1));
   return suite.finish("MultiCurlClient contract");
}
