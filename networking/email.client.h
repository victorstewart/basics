// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <curl/curl.h>

#pragma once

class EmailClient {
private:

  CURL *curl;

  struct upload_status {
    size_t bytes_read;
    String email;
  };

  static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
  {
    struct upload_status *upload_ctx = (struct upload_status *)userp;

    size_t max_copy_size = size * nmemb;
    size_t bytes_left = upload_ctx->email.size() - upload_ctx->bytes_read;
    size_t copy_size = (bytes_left < max_copy_size) ? bytes_left : max_copy_size;

    if (copy_size > 0)
    {
      memcpy(ptr, upload_ctx->email.data() + upload_ctx->bytes_read, copy_size);
      upload_ctx->bytes_read += copy_size;
      return copy_size;
    }

    return 0; // End of data
  }

  std::string insert_line_breaks(const std::string& body_text, size_t max_line_length = 80)
  {
    std::string result;
    size_t line_start = 0;
    size_t length = body_text.length();

    while (line_start < length)
    {
      size_t line_end = line_start + max_line_length;

      if (line_end >= length)
      {
        // If the remaining text is shorter than max_line_length, just add it to the result
        result += body_text.substr(line_start);
        break;
      }

      // Find the last space before or on the max_line_length position
      size_t last_space = body_text.rfind(' ', line_end);
      if (last_space == std::string::npos || last_space <= line_start)
      {
        // If no space found, or if the space is before the start of the line, break at max_line_length
        last_space = line_end;
      }

      // Add the substring to the result
      result += body_text.substr(line_start, last_space - line_start) + "\n";

      // Move to the next line and skip any leading spaces
      line_start = (last_space == line_end) ? last_space : last_space + 1;
      while (line_start < length && body_text[line_start] == ' ')
      {
        ++line_start;
      }
    }

    return result;
  }

public:

  void setUsername(StringType auto&& username) // user@example.com
  {
    String usernameText = {};
    usernameText.assign(username);
    curl_easy_setopt(curl, CURLOPT_USERNAME, usernameText.c_str());
  }

  void setPassword(StringType auto&& password) // zfiqfdmcwsfyejhs
  {
    String passwordText = {};
    passwordText.assign(password);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, passwordText.c_str());
  }

  void setSMTP(StringType auto&& smtp) // smtp://smtp.gmail.com:587
  {
    String smtpText = {};
    smtpText.assign(smtp);
    curl_easy_setopt(curl, CURLOPT_URL, smtpText.c_str());
  }

  void setTLSCAFile(StringType auto&& path)
  {
    String pathText = {};
    pathText.assign(path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, pathText.c_str());
  }

  void sendEmail(StringType auto&& from, StringType auto&& to, StringType auto&& subject, StringType auto&& body)
  {
    struct curl_slist *recipients = NULL;

    struct upload_status upload_ctx;
    upload_ctx.bytes_read = 0;

    String fromText = {};
    fromText.assign(from);
    String toText = {};
    toText.assign(to);
    String subjectText = {};
    subjectText.assign(subject);
    String bodyText = {};
    bodyText.assign(body);

    String& email = upload_ctx.email;
    email.snprintf_add<"To: {}\r\n"_ctv>(toText);
    email.snprintf_add<"From: {}\r\n"_ctv>(fromText);
    email.snprintf_add<"Subject: {}\r\n"_ctv>(subjectText);
    email.append("\r\n"_ctv);

    // now add body
    uint64_t line_start = 0;
    uint64_t max_line_width = 72;

    while (line_start < bodyText.size())
    {
      uint64_t line_end = line_start + max_line_width;

      if (line_end >= bodyText.size())
      {
        email.append(bodyText.substr(line_start, bodyText.size() - line_start, Copy::yes));
        email.append("\r\n"_ctv);
        break;
      }

      bool skipLastChar = false;

      if (int64_t first_line_break = bodyText.findChar('\n', line_start, line_end); first_line_break > -1)
      {
        line_end = first_line_break;
        skipLastChar = true;
      }
      else if (int64_t last_space = bodyText.rfindChar(' ', line_end, line_start); last_space > -1)
      {
        line_end = last_space;
        skipLastChar = true;
      }

      email.append(bodyText.substr(line_start, line_end - line_start, Copy::yes));
      email.append("\r\n"_ctv);

      line_start = line_end;
      if (skipLastChar)
      {
        line_start += 1;
      }

      while (line_start < bodyText.size() && bodyText.charAtIndex(line_start) == ' ')
      {
        ++line_start;
      }
    }

    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, fromText.c_str());
    recipients = curl_slist_append(recipients, toText.c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    curl_easy_perform(curl); // sync send

    // Clean up
    curl_slist_free_all(recipients);
  }

  ~EmailClient()
  {
    curl_easy_cleanup(curl);
  }

  EmailClient()
  {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
  }
};
