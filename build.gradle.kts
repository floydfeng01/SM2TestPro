// Top-level build file where you can add configuration options common to all sub-projects/modules.

buildscript {
    val ktVersion by extra("1.5.10")
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri(com.froad.buildsrc.BuildLibs.MavenCenter.aliYunUrl)
//            url = uri("http://maven.aliyun.com/nexus/content/groups/public/")
        }
    }
    dependencies {
        classpath (com.froad.buildsrc.BuildLibs.GradleTool.gradleTools)
        classpath (com.froad.buildsrc.BuildLibs.KtLibs.kotlinGradlePlugins)
//        classpath ("com.android.tools.build:gradle:4.2.2")
//        classpath ("org.jetbrains.kotlin:kotlin-gradle-plugin:${ktVersion}")

        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle files
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
        jcenter() // Warning: this repository is going to shut down soon
        maven {
            url = uri(com.froad.buildsrc.BuildLibs.MavenCenter.aliYunUrl)
        }
    }
}

tasks.register("clean", Delete::class.java) {
    delete (rootProject.buildDir)
}