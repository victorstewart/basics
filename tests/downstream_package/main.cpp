// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <ebpf/program.h>
#include <services/filesystem.h>

int main()
{
  BPFProgram program;
  String text("downstream package smoke");

  if (program.prog_fd != -1)
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

  return 0;
}
