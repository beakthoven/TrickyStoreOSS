/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.IBinder;
import android.os.IInterface;

import androidx.annotation.Nullable;

public interface IKeystoreSecurityLevel extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreSecurityLevel";

    KeyMetadata generateKey(KeyDescriptor key, @Nullable KeyDescriptor attestationKey,
            KeyParameter[] params, int flags, byte[] entropy);

    class Stub {
        public static IKeystoreSecurityLevel asInterface(IBinder b) {
            throw new RuntimeException();
        }
    }
}
