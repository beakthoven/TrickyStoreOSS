/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.hardware.security.keymint;

public @interface SecurityLevel {
    int KEYSTORE = 100;
    int SOFTWARE = 0;
    int STRONGBOX = 2;
    int TRUSTED_ENVIRONMENT = 1;
}
