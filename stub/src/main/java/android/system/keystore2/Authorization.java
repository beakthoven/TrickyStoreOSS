/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;

public class Authorization {
    public KeyParameter keyParameter;
    public int securityLevel = 0;
}
