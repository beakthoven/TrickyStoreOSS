/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.os.IBinder;

public interface IKeystoreService {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreService";

    IKeystoreSecurityLevel getSecurityLevel(int securityLevel);

    class Stub {
        public static IKeystoreService asInterface(IBinder b) {
            throw new RuntimeException("");
        }
    }
}
