/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.compat;

import android.hardware.security.keymint.IKeyMintDevice;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

/** Compile-only stub for the keystore2 legacy Keymaster compatibility service. */
public interface IKeystoreCompatService extends IInterface {
    IKeyMintDevice getKeyMintDevice(int securityLevel) throws RemoteException;

    abstract class Stub {
        public static IKeystoreCompatService asInterface(IBinder binder) {
            throw new UnsupportedOperationException("");
        }
    }
}
