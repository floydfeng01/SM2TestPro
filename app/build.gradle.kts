import com.froad.buildsrc.BuildLibs
import com.froad.buildsrc.BuildVersion

plugins {
    id ("com.android.application")
    id ("kotlin-android")
}

android {
    compileSdkVersion (BuildVersion.compileSdkVersion)
    buildToolsVersion (BuildVersion.buildToolsVersion)

    defaultConfig {
        applicationId = BuildVersion.applicationId
        minSdkVersion (BuildVersion.minSdkVersion)
        targetSdkVersion (BuildVersion.targetSdkVersion)
        versionCode = BuildVersion.versionCode
        versionName = BuildVersion.versionName

    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles (getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = BuildVersion.jvmVersion
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs ("libs")
        }
    }
}

dependencies {

//    implementation (fileTree (mapOf ("dir" to "libs", "include" to listOf ("*.jar", "*.aar"))))
    implementation (files ("libs/bc-15on-1.59.jar"))
    implementation (BuildLibs.KtLibs.kotlinStdlibs)
    implementation (BuildLibs.AndroidLibs.androidxCore)
    implementation (BuildLibs.AndroidLibs.androidxAppcompat)
    implementation (BuildLibs.AndroidLibs.androidMaterial)
    implementation (BuildLibs.AndroidLibs.androidxConstraintLayout)
    implementation (BuildLibs.CoroutineLibs.coroutinesAndroid)
}