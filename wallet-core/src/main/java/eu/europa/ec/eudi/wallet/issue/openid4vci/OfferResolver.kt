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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import eu.europa.ec.eudi.openid4vci.CredentialOffer
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import io.ktor.client.HttpClient
import org.jetbrains.annotations.VisibleForTesting
import java.net.URI

internal class OfferResolver(
    private val config: OpenId4VciManager.Config,
    private val ktorHttpClientFactory: () -> HttpClient,
    private val issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
) {

    private val resolveConfig: OpenId4VCIConfig by lazy {
        val clientId = when (val type = config.clientAuthenticationType) {
            is OpenId4VciManager.ClientAuthenticationType.None -> type.clientId
            is OpenId4VciManager.ClientAuthenticationType.AttestationBased -> type.clientId
        }
        OpenId4VCIConfig(
            clientId = clientId,
            authFlowRedirectionURI = URI.create(config.authFlowRedirectionURI),
            encryptionSupportConfig = config.responseEncryptionConfig,
            issuerMetadataPolicy = issuerMetadataPolicy,
        )
    }

    @VisibleForTesting
    val cache = mutableMapOf<String, Offer>()

    suspend fun resolve(offerUri: String, useCache: Boolean = true): Result<Offer> {
        return if (useCache) {
            cache[offerUri]?.let { Result.success(it) } ?: resolveAndCache(offerUri)
        } else resolveAndCache(offerUri)
    }

    private suspend fun resolveAndCache(offerUri: String): Result<Offer> {
        return ktorHttpClientFactory().use { httpClient ->
            CredentialOffer.resolve(
                httpClient = httpClient,
                config = resolveConfig,
                uri = offerUri,
            )
        }.map {
            Offer(it)
        }.also { result ->
            result
                .onSuccess { cache[offerUri] = it }
                .onFailure { cache.remove(offerUri) }
        }
    }
}
