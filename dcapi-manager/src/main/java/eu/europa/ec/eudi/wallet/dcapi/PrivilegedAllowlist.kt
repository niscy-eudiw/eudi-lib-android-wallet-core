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

package eu.europa.ec.eudi.wallet.dcapi

import android.content.Context

private const val DEFAULT_PRIVILEGED_ALLOWLIST_FILE = "privilegedUserAgents.json"

/**
 * Loads the default privileged allowlist JSON bundled with this library.
 *
 * The privileged allowlist defines which browsers/apps are trusted to act as
 * verifiers on behalf of a website (origin-bearing callers).
 *
 * Use this if you want to accept the same set of trusted browsers/apps as the
 * wallet-core default. Provide a custom JSON via
 * [eu.europa.ec.eudi.wallet.dcapi.DCAPIConfig.Builder.withPrivilegedAllowlist]
 * if your distribution has different trust requirements.
 *
 * @return the JSON content of the bundled `privilegedUserAgents.json` asset.
 */
fun Context.getDefaultPrivilegedUserAgents(): String =
    assets.open(DEFAULT_PRIVILEGED_ALLOWLIST_FILE).use { stream ->
        stream.readBytes().decodeToString()
    }
