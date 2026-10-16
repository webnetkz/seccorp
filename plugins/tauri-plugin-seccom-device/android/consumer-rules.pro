# SecCorp device plugin: Tauri calls it through reflection (@TauriPlugin, @Command,
# @InvokeArg, @ActivityCallback) and the Rust engine through JNI (NativeBridge),
# so R8 must keep its classes and member names in minified release builds.
-keep class com.webnetkz.seccom.device.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
