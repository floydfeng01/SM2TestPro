package com.froad.buildsrc

object BuildVersion {
    const val multidexVersion = "1.0.2"
    const val compileSdkVersion = 28
    const val buildToolsVersion = "28.0.3"
    const val minSdkVersion = 16
    const val targetSdkVersion = 28
    const val versionCode = 1
    const val versionName = "1.0"
    const val applicationId = "com.froad.sm2testpro"
    const val ktVersion = "1.5.10"
    const val jvmVersion = "1.8"
    const val coroutines = "1.3.9"

}

object BuildLibs {
    object MavenCenter {
        const val aliYunUrl = "http://maven.aliyun.com/nexus/content/groups/public/"
    }

    object GradleTool {
        const val gradleTools = "com.android.tools.build:gradle:4.2.2"
    }

    object KtLibs{
        const val kotlinStdlibs = "org.jetbrains.kotlin:kotlin-stdlib:${BuildVersion.ktVersion}"
        const val kotlinGradlePlugins = "org.jetbrains.kotlin:kotlin-gradle-plugin:${BuildVersion.ktVersion}"
    }

    object AndroidLibs{
        const val androidxCore = "androidx.core:core-ktx:1.3.1"
        const val androidxAppcompat = "androidx.appcompat:appcompat:1.2.0"
        const val androidxConstraintLayout = "androidx.constraintlayout:constraintlayout:2.0.1"
        const val androidMaterial = "com.google.android.material:material:1.2.1"
    }

    object CoroutineLibs {
        const val coroutinesAndroid = "org.jetbrains.kotlinx:kotlinx-coroutines-android:${BuildVersion.coroutines}"
    }
}