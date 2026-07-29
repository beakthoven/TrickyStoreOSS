/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class ExportResult implements Parcelable {
    public final byte[] exportData;
    public final int resultCode;

    public ExportResult(int resultCode) {
        this.resultCode = resultCode;
        this.exportData = new byte[0];
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    public static final Creator<ExportResult> CREATOR = new Creator<ExportResult>() {
        @Override
        public ExportResult createFromParcel(Parcel in) {
            throw new RuntimeException("");
        }

        @Override
        public ExportResult[] newArray(int size) {
            throw new RuntimeException("");
        }
    };
}
