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

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.KeyGenerationConfig
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.wallet.document.format.DocumentFormat
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.DocTypeFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.VctFilter
import io.ktor.client.HttpClient
import java.net.URI

/**
 * Creates an [Issuer] from the given [Offer].
 */
internal class IssuerCreator(
    private val config: OpenId4VciManager.Config,
    private val ktorHttpClientFactory: () -> HttpClient,
) {

    /**
     * Creates an [Issuer] from the given [Offer].
     * @param offer The [Offer].
     * @return The [Issuer].
     */
    fun createIssuer(offer: Offer): Issuer {
        val credentialOffer = offer.credentialOffer
        return Issuer.make(config.toOpenId4VCIConfig(), credentialOffer, ktorHttpClientFactory)
            .getOrThrow()
    }

    /**
     * Creates an [Issuer] from the given [CredentialConfigurationIdentifier]s.
     * @param credentialConfigurationIdentifiers The [CredentialConfigurationIdentifier]s.
     * @return The [Issuer].
     */
    suspend fun createIssuer(credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>): Issuer {
        return Issuer.makeWalletInitiated(
            config = config.toOpenId4VCIConfig(),
            credentialIssuerId = CredentialIssuerId(config.issuerUrl).getOrThrow(),
            credentialConfigurationIdentifiers = credentialConfigurationIdentifiers,
            ktorHttpClientFactory = ktorHttpClientFactory
        ).getOrThrow()
    }

    suspend fun createIssuer(documentFormat: DocumentFormat): Issuer {
        val formatFilter = when (documentFormat) {
            is MsoMdocFormat -> DocTypeFilter(documentFormat.docType)
            is SdJwtVcFormat -> VctFilter(documentFormat.vct)
        }

        return CredentialIssuerId(config.issuerUrl)
            .mapCatching { createIssuerId ->
                ktorHttpClientFactory().use { client ->
                    Issuer.metaData(
                        httpClient = client,
                        credentialIssuerId = createIssuerId,
                        policy = IssuerMetadataPolicy.IgnoreSigned
                    )
                }
            }
            .mapCatching { (issuerMetadata, _) ->
                val configurationId = issuerMetadata
                    .credentialConfigurationsSupported
                    .filterValues { conf -> formatFilter(conf) }
                    .firstNotNullOfOrNull { (confId, _) -> confId }
                    ?: throw IllegalStateException("No suitable configuration found")

                createIssuer(listOf(configurationId))
            }
            .getOrThrow()
    }

    /**
     * Converts the [OpenId4VciManager.Config] to [OpenId4VCIConfig].
     * @receiver The [OpenId4VciManager.Config].
     * @return The [OpenId4VCIConfig].
     */
    private fun OpenId4VciManager.Config.toOpenId4VCIConfig(): OpenId4VCIConfig {
        return OpenId4VCIConfig(
            clientId = clientId,
            authFlowRedirectionURI = URI.create(authFlowRedirectionURI),
            keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
            dPoPSigner = if (useDPoPIfSupported) JWSDPoPSigner().getOrNull() else null,
            parUsage = when (parUsage) {
                OpenId4VciManager.Config.ParUsage.IF_SUPPORTED -> ParUsage.IfSupported
                OpenId4VciManager.Config.ParUsage.REQUIRED -> ParUsage.Required
                OpenId4VciManager.Config.ParUsage.NEVER -> ParUsage.Never
                else -> ParUsage.IfSupported
            }
        )
    }
}