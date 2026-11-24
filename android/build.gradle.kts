// Versions are pinned to what is already in the local Gradle cache where possible.
// AGP 8.8.1 needs Gradle 8.10.2; Chaquopy 17.2 supports AGP 7.3 - 9.5.
plugins {
    id("com.android.application") version "8.8.1" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
    id("com.chaquo.python") version "17.2.0" apply false
}
