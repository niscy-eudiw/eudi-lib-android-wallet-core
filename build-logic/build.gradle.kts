plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.android.gradle.plugin)
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.dokka.gradle.plugin)
    implementation(libs.dependencycheck.gradle.plugin)
    implementation(libs.sonarqube.gradle.plugin)
    implementation(libs.kover.gradle.plugin)
    implementation(libs.maven.publish.gradle.plugin)
}
