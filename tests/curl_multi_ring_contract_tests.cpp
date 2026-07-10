// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/curl.multi.ring.h>

static_assert(CurlMultiRingClient::maximumTransfers == 256);
static_assert(CurlMultiRingClient::maximumRequestHeaders == 32);
static_assert(CurlMultiRingClient::maximumHeaderBytes == 32 * 1024);
static_assert(CurlMultiRingClient::maximumResponseBytes == 16 * 1024 * 1024);
static_assert(CurlMultiRingClient::maximumSocketWatches == 1024);
static_assert(CurlMultiRingClient::maximumStagedSocketEvents == 4096);
static_assert(CurlMultiRingClient::maximumConcurrentStreams == 32);

int main()
{
   TestSuite suite;
   CurlMultiRingClient::Request request;
   request.url = "https://127.0.0.1/";
   request.resolveHost = "127.0.0.1";
   request.headers.push_back({"Accept", "application/json"});
   EXPECT_TRUE(suite, request.headers.size() == 1);
   EXPECT_TRUE(suite, request.httpPolicy == CurlMultiRingClient::HttpPolicy::preferHttp2);
   EXPECT_TRUE(suite, request.tlsMinimum == CurlMultiRingClient::TlsMinimum::tls12);
   return suite.finish("curl multi Ring contract");
}
