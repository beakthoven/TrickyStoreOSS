/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.hardware.security.keymint;

public @interface KeyPurpose {
    int AGREE_KEY = 6;
    int ATTEST_KEY = 7;
    int DECRYPT = 1;
    int ENCRYPT = 0;
    int SIGN = 2;
    int VERIFY = 3;
    int WRAP_KEY = 5;
}
