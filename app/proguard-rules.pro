# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-keepclasseswithmembers class io.github.beakthoven.TrickyStoreOSS.MainKt {
    public static void main(java.lang.String[]);
}

-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# keep these or bouncycastle will not work
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

# Keep all interceptor classes and their methods - used via reflection and JNI
-keep class io.github.beakthoven.TrickyStoreOSS.interceptors.** {
    *;
}

# Keep SecurityLevelInterceptor and its inner classes
-keep class io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor {
    *;
}

# Keep Key and Info inner classes used in maps - critical for runtime
-keepclassmembers class io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor$Key {
    *;
}
-keepclassmembers class io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor$Info {
    *;
}

# Keep Parcelable CREATOR fields
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

-repackageclasses
-allowaccessmodification
-overloadaggressively
-keepattributes SourceFile,LineNumberTable,LocalVariableTable
-renamesourcefileattribute