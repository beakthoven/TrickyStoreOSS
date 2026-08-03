/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import com.android.build.api.variant.ApplicationVariant

plugins { alias(libs.plugins.android.application) }

val gitCommitCount =
    providers
        .exec {
            commandLine("git", "rev-list", "HEAD", "--count")
            workingDir = rootDir
        }
        .standardOutput
        .asText
        .map { it.trim().toInt() }
        .get()

val gitCommitHash =
    providers
        .exec {
            commandLine("git", "rev-parse", "--verify", "--short", "HEAD")
            workingDir = rootDir
        }
        .standardOutput
        .asText
        .map { it.trim() }
        .get()

val verName = "v3.0.0"

android {
    namespace = "io.github.beakthoven.TrickyStoreOSS"
    compileSdk = 37
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.github.beakthoven.TrickyStoreOSS"
        minSdk = 29
        targetSdk = 37
        versionCode = gitCommitCount
        versionName = verName

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
                arguments += "-DCMAKE_BUILD_TYPE=Release"
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                arguments += "-DANDROID_ALLOW_UNDEFINED_SYMBOLS=ON"
                arguments += "-DCMAKE_CXX_STANDARD=23"
                arguments += "-DCMAKE_C_STANDARD=23"
                arguments += "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"

                cppFlags += "-std=c++23"
                cppFlags += "-fno-exceptions"
                cppFlags += "-fno-rtti"
                cppFlags += "-fvisibility=hidden"
                cppFlags += "-fvisibility-inlines-hidden"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_24
        targetCompatibility = JavaVersion.VERSION_24
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.28.0+"
        }
    }
    buildFeatures {
        prefab = true
    }
    packaging {
        resources {
            pickFirsts += setOf(
                "META-INF/LICENSE.md",
                "META-INF/NOTICE.md",
                "META-INF/INDEX.LIST",
            )
        }
    }
}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.org.bouncycastle.bcpkix.jdk18on)
    implementation(libs.org.lsposed.libcxx.libcxx)
}

androidComponents {
    onVariants { variant: ApplicationVariant ->
        val variantName = variant.name
        val capitalized = variantName.replaceFirstChar { it.uppercase() }
        val tempModuleDir = project.layout.buildDirectory.dir("tmp/module-${variantName}")

        tasks.register("copyFiles${capitalized}") {
            val moduleFolder = project.rootDir.resolve("module")
            val buildDir = project.layout.buildDirectory

            doLast {
                val isDebug = variantName.contains("debug", ignoreCase = true)

                listOf("service.apk", "classes.dex").forEach { fileName ->
                    val oldFile = moduleFolder.resolve(fileName)
                    if (oldFile.exists()) oldFile.delete()
                }

                val sourceFile =
                    if (isDebug) {
                        buildDir.get().asFile.resolve("outputs/apk/$variantName/app-$variantName.apk")
                    } else {
                        buildDir.get().asFile.resolve("intermediates/dex/release/minifyReleaseWithR8/classes.dex")
                    }

                val destFileName = if (isDebug) "service.apk" else "classes.dex"
                sourceFile.copyTo(moduleFolder.resolve(destFileName), overwrite = true)

                val soDir =
                    buildDir
                        .get()
                        .asFile
                        .resolve("intermediates/stripped_native_libs/$variantName/strip${capitalized}DebugSymbols/out/lib")

                val allowedLibs = setOf("libinject.so", "libTrickyStoreOSS.so")
                soDir
                    .walk()
                    .filter { it.isFile && it.name in allowedLibs }
                    .forEach { soFile ->
                        val abiFolder = soFile.parentFile.name
                        val destination = moduleFolder.resolve("lib/$abiFolder/${soFile.name}")
                        soFile.copyTo(destination, overwrite = true)
                    }
            }
        }

        // Prepare temp directory with all files

        tasks.register("prepareModuleFiles${capitalized}") {
            dependsOn("copyFiles${capitalized}")
            val sourceDir = project.rootDir.resolve("module")
            val commitCount = gitCommitCount
            val commitHash = gitCommitHash
            val versionName = verName
            val variant = variantName
            val tempDirProvider = tempModuleDir

            doLast {
                val tempDir = tempDirProvider.get().asFile

                // Clean and create temp directory
                tempDir.deleteRecursively()
                tempDir.mkdirs()

                // Copy all files except module.prop
                sourceDir
                    .walkTopDown()
                    .filter { it.isFile && it.name != "module.prop" }
                    .forEach { sourceFile ->
                        val relativePath = sourceFile.relativeTo(sourceDir)
                        val destFile = tempDir.resolve(relativePath)
                        destFile.parentFile.mkdirs()
                        sourceFile.copyTo(destFile, overwrite = true)
                    }

                // Process module.prop
                val sourceProp = sourceDir.resolve("module.prop")
                val destProp = tempDir.resolve("module.prop")
                val content = sourceProp.readText()
                val processedContent =
                    content
                        .replace("REPLACEMEVERCODE", commitCount.toString())
                        .replace("REPLACEMEVER", "$versionName ($commitCount-$commitHash-$variant)")
                destProp.writeText(processedContent)
            }
        }

        // Zip task uses the temp directory
        tasks.register<Zip>("zip${capitalized}") {
            dependsOn("prepareModuleFiles${capitalized}")
            archiveFileName.set("Tricky-Store-OSS-$verName-$gitCommitCount-$gitCommitHash-${capitalized}.zip")
            destinationDirectory.set(project.rootDir.resolve("out"))
            from(tempModuleDir)
        }

        tasks.matching { it.name == "assemble${capitalized}" }.configureEach { finalizedBy("zip${capitalized}") }
    }
}
