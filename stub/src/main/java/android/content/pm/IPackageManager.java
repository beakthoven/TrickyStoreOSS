/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.content.pm;

import android.os.IBinder;

public interface IPackageManager {
    String[] getPackagesForUid(int uid);

    int checkPermission(String permName, String pkgName, int userId);

    PackageInfo getPackageInfo(String packageName, long flags, int userId);

    PackageInfo getPackageInfo(String packageName, int flags, int userId);

    ParceledListSlice<PackageInfo> getInstalledPackages(int flags, int userId);

    ParceledListSlice<PackageInfo> getInstalledPackages(long flags, int userId);

    class Stub {
        public static IPackageManager asInterface(IBinder binder) {
            throw new RuntimeException("");
        }
    }
}
