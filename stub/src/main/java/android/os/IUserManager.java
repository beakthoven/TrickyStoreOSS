/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.os;

public interface IUserManager {
    boolean isUserUnlocked(int userId);

    class Stub {
        public static IUserManager asInterface(IBinder binder) {
            throw new RuntimeException("");
        }
    }
}
