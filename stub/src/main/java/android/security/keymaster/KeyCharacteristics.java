/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyCharacteristics implements Parcelable {
    public KeymasterArguments hwEnforced;
    public KeymasterArguments swEnforced;

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    public static final Creator<KeyCharacteristics> CREATOR = new Creator<KeyCharacteristics>() {
        @Override
        public KeyCharacteristics createFromParcel(Parcel in) {
            throw new RuntimeException("");
        }

        @Override
        public KeyCharacteristics[] newArray(int size) {
            throw new RuntimeException("");
        }
    };
}
