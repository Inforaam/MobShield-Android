/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mobshield_native.h"

#include <cstring>

#include "mobshield_buildinfo.h"

namespace {
bool g_initialized = false;

// Kept in .rodata so mobshieldVerify can check that libmobshieldcore.so was built with this build's
// header. The build ID is public; nothing secret may be embedded here.
__attribute__((used, retain)) static const char kMobShieldBuildIdAnchor[] =
    "MOBSHIELD_BUILD_ID=" MOBSHIELD_BUILD_ID;
}  // namespace

int mobshield_native_init(void) {
    (void)kMobShieldBuildIdAnchor[0];
    g_initialized = true;
    return 0;
}

int mobshield_native_get_build_id(char* out, int out_len) {
    if (out == nullptr || out_len <= 0) {
        return -1;
    }
    const char* value = MOBSHIELD_BUILD_ID;
    const int needed = static_cast<int>(std::strlen(value));
    if (needed >= out_len) {
        return -1;
    }
    std::strcpy(out, value);
    return needed;
}

int mobshield_native_get_version(char* out, int out_len) {
    if (out == nullptr || out_len <= 0) {
        return -1;
    }
    const char* value = MOBSHIELD_VERSION;
    const int needed = static_cast<int>(std::strlen(value));
    if (needed >= out_len) {
        return -1;
    }
    std::strcpy(out, value);
    return needed;
}

int mobshield_native_self_check(void) {
    if (!g_initialized) {
        return 0;
    }
    return MOBSHIELD_SELF_CHECK_MAGIC;
}
