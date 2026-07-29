/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keystore;

import android.os.IBinder;
import android.os.RemoteException;
import android.security.keymaster.ExportResult;

public interface IKeystoreExportKeyCallback {
    void onFinished(ExportResult exportResult) throws RemoteException;

    public static abstract class Stub {
        public static IKeystoreExportKeyCallback asInterface(IBinder b) {
            throw new RuntimeException("");
        }
    }
}
