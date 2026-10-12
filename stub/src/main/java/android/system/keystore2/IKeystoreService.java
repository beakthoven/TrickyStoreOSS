/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.os.IBinder;
import android.os.RemoteException;

public interface IKeystoreService {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreService";

    IKeystoreSecurityLevel getSecurityLevel(int securityLevel) throws RemoteException;

    void deleteKey(KeyDescriptor key) throws RemoteException;

    class Stub {
        public static IKeystoreService asInterface(IBinder b) {
            throw new RuntimeException("");
        }
    }
}
