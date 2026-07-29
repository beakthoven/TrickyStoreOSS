/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

abstract class KeymasterArgument implements Parcelable {
    public final int tag;

    protected KeymasterArgument(int tag) {
        this.tag = tag;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    public static final Creator<KeymasterArgument> CREATOR = new Creator<KeymasterArgument>() {
        @Override
        public KeymasterArgument createFromParcel(Parcel in) {
            throw new RuntimeException("");
        }

        @Override
        public KeymasterArgument[] newArray(int size) {
            throw new RuntimeException("");
        }
    };
}
