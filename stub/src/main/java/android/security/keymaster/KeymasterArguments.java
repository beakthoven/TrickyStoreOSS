/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

public class KeymasterArguments implements Parcelable {

    private static final long UINT32_RANGE = 1L << 32;
    public static final long UINT32_MAX_VALUE = UINT32_RANGE - 1;

    private static final BigInteger UINT64_RANGE = BigInteger.ONE.shiftLeft(64);
    public static final BigInteger UINT64_MAX_VALUE = UINT64_RANGE.subtract(BigInteger.ONE);

    private List<KeymasterArgument> mArguments;

    public static final @NonNull Parcelable.Creator<KeymasterArguments> CREATOR = new Parcelable.Creator<KeymasterArguments>() {
        @Override
        public KeymasterArguments createFromParcel(Parcel in) {
            throw new RuntimeException("");
        }

        @Override
        public KeymasterArguments[] newArray(int size) {
            throw new RuntimeException("");
        }
    };

    public KeymasterArguments() {
        throw new RuntimeException("");
    }

    private KeymasterArguments(Parcel in) {
        throw new RuntimeException("");
    }

    public void addEnum(int tag, int value) {
        throw new RuntimeException("");
    }

    public void addEnums(int tag, int... values) {
        throw new RuntimeException("");
    }

    public int getEnum(int tag, int defaultValue) {
        throw new RuntimeException("");
    }

    public List<Integer> getEnums(int tag) {
        throw new RuntimeException("");
    }

    private void addEnumTag(int tag, int value) {
        throw new RuntimeException("");
    }

    private int getEnumTagValue(KeymasterArgument arg) {
        throw new RuntimeException("");
    }

    public void addUnsignedInt(int tag, long value) {
        throw new RuntimeException("");
    }

    public long getUnsignedInt(int tag, long defaultValue) {
        throw new RuntimeException("");
    }

    public void addUnsignedLong(int tag, BigInteger value) {
        throw new RuntimeException("");
    }

    public List<BigInteger> getUnsignedLongs(int tag) {
        throw new RuntimeException("");
    }

    private void addLongTag(int tag, BigInteger value) {
        throw new RuntimeException("");
    }

    private BigInteger getLongTagValue(KeymasterArgument arg) {
        throw new RuntimeException("");
    }

    public void addBoolean(int tag) {
        throw new RuntimeException("");
    }

    public boolean getBoolean(int tag) {
        throw new RuntimeException("");
    }

    public void addBytes(int tag, byte[] value) {
        throw new RuntimeException("");
    }

    public byte[] getBytes(int tag, byte[] defaultValue) {
        throw new RuntimeException("");
    }

    public void addDate(int tag, Date value) {
        throw new RuntimeException("");
    }

    public void addDateIfNotNull(int tag, Date value) {
        throw new RuntimeException("");
    }

    public Date getDate(int tag, Date defaultValue) {
        throw new RuntimeException("");
    }

    private KeymasterArgument getArgumentByTag(int tag) {
        throw new RuntimeException("");
    }

    public boolean containsTag(int tag) {
        throw new RuntimeException("");
    }

    public int size() {
        throw new RuntimeException("");
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        throw new RuntimeException("");
    }

    public void readFromParcel(Parcel in) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    public static BigInteger toUint64(long value) {
        throw new RuntimeException("");
    }
}