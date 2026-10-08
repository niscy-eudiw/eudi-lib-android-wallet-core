/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.Logging
import io.ktor.client.plugins.pluginOrNull
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertNull

class DefaultOpenId4VciManagerHttpClientTest {

    @Test
    fun `the issuance HTTP client does not log traffic`() {
        val manager = DefaultOpenId4VciManager(
            context = mockk(relaxed = true),
            documentManager = mockk(),
            walletAttestationKeyManager = mockk(),
            config = mockk(),
            logger = { },
            ktorHttpClientFactory = { HttpClient() },
        )

        assertNull(manager.httpClientFactory().pluginOrNull(Logging))
    }
}
