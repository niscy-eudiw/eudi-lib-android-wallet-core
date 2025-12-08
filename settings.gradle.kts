/*
 * Copyright (c) 2024-2025 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        maven {
            url = uri("https://central.sonatype.com/repository/maven-snapshots/")
            mavenContent { snapshotsOnly() }
        }
    }
}

// Include local libraries for multipaz 0.95 migration
includeBuild("../eudi-lib-android-wallet-document-manager") {
    dependencySubstitution {
        substitute(module("eu.europa.ec.eudi:eudi-lib-android-wallet-document-manager"))
            .using(project(":document-manager"))
    }
}

includeBuild("../eudi-lib-android-iso18013-data-transfer") {
    dependencySubstitution {
        substitute(module("eu.europa.ec.eudi:eudi-lib-android-iso18013-data-transfer"))
            .using(project(":transfer-manager"))
    }
}

rootProject.name = "eudi-lib-android-wallet-core"
include(":wallet-core")
