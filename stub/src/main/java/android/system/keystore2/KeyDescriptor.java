/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyDescriptor implements Parcelable {
    public String alias;
    public byte[] blob;
    public int domain = 0;
    public long nspace = 0;

    public static final Creator<KeyDescriptor> CREATOR = new Creator<KeyDescriptor>() {
        @Override
        public KeyDescriptor createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public KeyDescriptor[] newArray(int size) {
            throw new RuntimeException();
        }
    };

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new RuntimeException("");
    }
}
