// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <sys/types.h>

#include <string>
#include <string_view>
#include <vector>

namespace ts {

struct MapInfo {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint8_t perms = 0;
    bool is_private = false;
    uintptr_t offset = 0;
    dev_t dev = 0;
    ino_t inode = 0;
    std::string path;

    static std::vector<MapInfo> Scan(std::string_view pid = "self");
};

} // namespace ts
