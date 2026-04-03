// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "includes.h"

#include "base/reflection.h"
#include "services/filesystem.h"
#include "services/memfd.h"
#include "services/vault.h"
#include "types/types.containers.h"

int main()
{
  String value("alpha");

  Vector<int> numbers;
  numbers.push_back(7);

  String encoded;
  Base64::encode(reinterpret_cast<const uint8_t *>("ok"), 2, encoded);

  String filename = Filesystem::filenameFromPath(String("/tmp/file.txt"));
  std::string_view reflected = type_name<int>();
  bool invalidMemfdWriteRejected = (Memfd::writeAll(-1, value) == false);
  Vault::SSHKeyPackage package;
  package.clear();

  if (value.size() != 5 || numbers.size() != 1 || encoded.size() == 0 || filename != "file.txt"_ctv ||
      reflected.find("int") == std::string_view::npos || invalidMemfdWriteRejected == false ||
      package.privateKeyOpenSSH.size() != 0 || package.publicKeyOpenSSH.size() != 0)
  {
    return 1;
  }

  return 0;
}
