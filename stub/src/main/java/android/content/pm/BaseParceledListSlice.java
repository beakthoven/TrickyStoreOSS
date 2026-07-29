/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.content.pm;

import java.util.List;

abstract class BaseParceledListSlice<T> {

    public List<T> getList() {
        throw new RuntimeException("");
    }
}