// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <android/log.h>

#include <cstdarg>

#include "logging.hpp"

namespace logging {
void log(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(prio, tag, fmt, ap);
    va_end(ap);
}
} // namespace logging