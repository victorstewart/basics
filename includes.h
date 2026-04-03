// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

using uint128_t = __uint128_t;
using int128_t = __int128_t;

#ifndef BASICS_DEBUG
#define BASICS_DEBUG 0
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#include <enums/memory.h>

#include <macros/global.h>

#include <services/debug.h>
#include <services/random.h>
#include <services/hash.h>
#include <services/memory.h>

namespace Crypto {
static void fillWithSecureRandomBytes(uint8_t *buffer, uint32_t nBytes);
}

#include <types/types.string.h>

#include <services/base64.h>
#include <services/base62.h>
