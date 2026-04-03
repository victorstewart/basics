// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <vector>

#include "includes.h"

int main()
{
  String output;
  output.snprintf<"{}"_ctv>(std::vector<int> {1, 2, 3});
  return 0;
}
