/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keystore;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.security.keymaster.KeyCharacteristics;

public interface IKeystoreKeyCharacteristicsCallback extends IInterface {
    void onFinished(KeystoreResponse keystoreResponse, KeyCharacteristics keyCharacteristics) throws RemoteException;

    public static abstract class Stub {
        public static IKeystoreKeyCharacteristicsCallback asInterface(IBinder b) {
            throw new RuntimeException("");
        }
    }
}
