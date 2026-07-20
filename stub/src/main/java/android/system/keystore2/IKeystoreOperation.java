/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;

public interface IKeystoreOperation extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    void updateAad(byte[] aadInput);

    byte[] update(byte[] input);

    byte[] finish(byte[] input, byte[] signature);

    void abort() throws android.os.RemoteException;

    abstract class Stub extends Binder implements IKeystoreOperation {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public IBinder asBinder() {
            return this;
        }
    }
}
