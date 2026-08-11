/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.hardware.security.keymint;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

/** Compile-only stub for the platform KeyMint stable AIDL interface. */
public interface IKeyMintDevice extends IInterface {
    String DESCRIPTOR = "android.hardware.security.keymint.IKeyMintDevice";

    KeyMintHardwareInfo getHardwareInfo() throws RemoteException;

    int getInterfaceVersion() throws RemoteException;

    abstract class Stub {
        public static IKeyMintDevice asInterface(IBinder binder) {
            throw new UnsupportedOperationException("");
        }
    }
}
