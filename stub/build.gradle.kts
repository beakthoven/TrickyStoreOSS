/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.beakthoven.stub"
    compileSdk = 37
    defaultConfig {
        minSdk = 29
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies {
    compileOnly(libs.annotation)
}