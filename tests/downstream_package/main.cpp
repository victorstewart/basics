// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <networking/message.h>
#include <services/filesystem.h>

#if defined(BASICS_DOWNSTREAM_ENABLE_TIDESDB) && BASICS_DOWNSTREAM_ENABLE_TIDESDB
#include <databases/embedded/tidesdb.h>
#endif

int main()
{
  String text("downstream package smoke");
  String packet;
  Message::appendValue(packet, text.data(), uint32_t(text.size()));
#if defined(BASICS_DOWNSTREAM_ENABLE_TIDESDB) && BASICS_DOWNSTREAM_ENABLE_TIDESDB
  TidesDB db;
#endif

  if (packet.size() <= text.size())
  {
    return 1;
  }

  if (text.equals("downstream package smoke"_ctv) == false)
  {
    return 1;
  }

  if (Filesystem::fileExists("/dev/null"_ctv) == false)
  {
    return 1;
  }

#if defined(BASICS_DOWNSTREAM_ENABLE_TIDESDB) && BASICS_DOWNSTREAM_ENABLE_TIDESDB
  if (db.path().size() != 0)
  {
    return 1;
  }
#endif

  return 0;
}
