/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.hardware.security.keymint;

public @interface Algorithm {
    int AES = 32;
    int EC = 3;
    int HMAC = 128;
    int RSA = 1;
    int TRIPLE_DES = 33;
}
