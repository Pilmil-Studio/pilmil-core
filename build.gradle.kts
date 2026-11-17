plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kover)
    alias(libs.plugins.detekt) apply false
}

dependencies {
    kover(project(":core-platform"))
    kover(project(":core-designsystem"))
}

subprojects {
    apply(plugin = "org.jetbrains.kotlinx.kover")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    extensions.configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
        buildUponDefaultConfig = true
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        parallel = true
    }

    tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
        setSource(files("src/commonMain/kotlin", "src/androidMain/kotlin", "src/iosMain/kotlin"))
        include("**/*.kt")
        exclude("**/build/**")
        reports {
            html.required.set(true)
            xml.required.set(false)
            txt.required.set(true)
        }
    }
}

allprojects {
    group = "fr.pilmil.core"
    version = "0.1.0"
}
