rootProject.name = "pilmil-core"

val localProps = file("local.properties")
val parentProps = file("../local.properties")
if (!localProps.exists() && parentProps.exists() && System.getenv("ANDROID_HOME") == null) {
    parentProps.copyTo(localProps)
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

include(":core-platform")
include(":core-designsystem")
