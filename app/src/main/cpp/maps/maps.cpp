// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "maps.hpp"

#include <cctype>
#include <cstdio>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace ts {

std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    std::vector<MapInfo> infos;

    std::string path = "/proc/" + std::string{pid} + "/maps";
    auto *fp = fopen(path.c_str(), "r");
    if (!fp) return infos;

    char *line = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, fp)) > 0) {
        line[read - 1] = '\0';

        uintptr_t start = 0, end = 0, off = 0;
        ino_t inode = 0;
        unsigned int dev_major = 0, dev_minor = 0;
        char perm[5] = {0};
        int path_off = 0;

        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %x:%x %lu %n",
                   &start, &end, perm, &off, &dev_major, &dev_minor, &inode,
                   &path_off) != 7) {
            continue;
        }

        while (path_off < read && isspace(static_cast<unsigned char>(line[path_off])))
            path_off++;

        auto &info = infos.emplace_back();
        info.start = start;
        info.end = end;
        info.is_private = perm[3] == 'p';
        info.offset = off;
        info.dev = static_cast<dev_t>(makedev(dev_major, dev_minor));
        info.inode = inode;
        info.path = line + path_off;

        if (perm[0] == 'r') info.perms |= PROT_READ;
        if (perm[1] == 'w') info.perms |= PROT_WRITE;
        if (perm[2] == 'x') info.perms |= PROT_EXEC;
    }

    free(line);
    fclose(fp);
    infos.shrink_to_fit();
    return infos;
}

} // namespace ts
