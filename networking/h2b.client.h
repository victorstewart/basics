// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <curl/curl.h>
#include <simdjson.h>

#pragma once

class H2BlockingClient {
protected:

  CURL *curl;
  String response;
  simdjson::dom::parser parser;
  struct curl_slist *headers = NULL;

  static size_t response_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
  {
    size_t realsize = size * nmemb;

    static_cast<H2BlockingClient *>(userdata)->response.append(ptr, realsize);

    return realsize;
  }

  template <StringType T>
  void doRequest(T&& url)
  {
    String urlText = {};
    urlText.assign(url);
    curl_easy_setopt(curl, CURLOPT_URL, urlText.c_str());

    response.clear();
    curl_easy_perform(curl);
  }

  template <StringType T>
  simdjson::simdjson_result<simdjson::dom::element> getJSONResponse(T&& url)
  {
    doRequest(std::forward<T>(url));

    response.need(simdjson::SIMDJSON_PADDING);

    // we have to return the document because it must be retained
    return parser.parse(response.data(), response.size(), false);
  }

  void configure(void)
  {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    // curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6); // ipv6 only
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);

    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<H2BlockingClient *>(this));

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8"); // we might want to selectively send this, but if it doesn't break anything then fine

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  ~H2BlockingClient()
  {
    if (headers != NULL)
    {
      curl_slist_free_all(headers);
      headers = NULL;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
  }

  H2BlockingClient()
  {
    configure();
  }

public:

  void setTLSCAFile(StringType auto&& path)
  {
    String pathText = {};
    pathText.assign(path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, pathText.c_str());
  }
};
