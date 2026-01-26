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

package eu.europa.ec.eudi.wallet.openid4vci

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.AuthorizationCode
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataResolver
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestResolver
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.EcConfig
import eu.europa.ec.eudi.openid4vci.EncryptionSupportConfig
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.IssuerTrust
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.RsaConfig
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DocumentManager
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.net.URI

suspend fun DocumentManager.Companion.make(builder: suspend DocumentManager.Builder.() -> Unit): DocumentManager {
    return DocumentManager.Builder().apply {
        runBlocking { builder() }
    }.build()
}

fun example() {

    val httpClient = HttpClient { }

    runBlocking {

        val documentManager = DocumentManager.make {
            storage = EphemeralStorage()
            secureAreaRepository = SecureAreaRepository.Builder()
                .add(SoftwareSecureArea.create(EphemeralStorage()))
                .build()
        }

        val metadata = CredentialIssuerMetadataResolver(httpClient).resolve(
            issuer = CredentialIssuerId(value = "https://dev.issuer.eudiw.dev").getOrThrow(),
            policy = IssuerMetadataPolicy.IgnoreSigned,
        ).getOrThrow()

        val offer = CredentialOfferRequestResolver(httpClient, IssuerMetadataPolicy.IgnoreSigned)
            .resolve("https://dev.issuer.eudiw.dev/credential-offer").getOrThrow()

        val config = OpenId4VCIConfig(
            authFlowRedirectionURI = URI("myapp://callback"),
            clientAuthentication = ClientAuthentication.None(id = "my-client-id"),
            encryptionSupportConfig = EncryptionSupportConfig(
                credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
                ecConfig = EcConfig(Curve.P_256),
                rsaConfig = RsaConfig(rcaKeySize = 2048),
            ),
            parUsage = ParUsage.IfSupported,
            issuerMetadataPolicy = IssuerMetadataPolicy.RequireSigned(
                issuerTrust = IssuerTrust.ByCertificateChain { chain ->
                    // Validate the certificate chain
                    true
                }
            )
        )

        val issuer = Issuer.make(config, offer, httpClient).getOrThrow()

        // authorization
        val authorizedRequestRrepared = issuer.prepareAuthorizationRequest().getOrThrow()

        val authorizationCode =
            AuthorizationCode("") // Obtain authorization code through user interaction or pre-authorization
        val serverState = "" // Obtain server state if applicable
        var authorizedRequest = with(issuer) {
            authorizedRequestRrepared.authorizeWithAuthorizationCode(authorizationCode, serverState)
        }.getOrThrow()


        // issuance requests

        offer.credentialConfigurations.forEach { (id, config) ->
            val pendingDocument = documentManager.createDocument(
                credentialConfigurationIdentifier = id,
                credentialConfiguration = config,
                createDocumentSettings = CreateDocumentSettings(
                    secureAreaIdentifier = SoftwareSecureArea.IDENTIFIER,
                    createKeySettings = SoftwareCreateKeySettings.Builder().build(),
                    numberOfCredentials = offer.batchCredentialIssuanceSize,
                    credentialPolicy = CreateDocumentSettings.CredentialPolicy.RotateUse,
                ),
                credentialOffer = offer
            ).getOrThrow()

            val proofsSpecification =
                pendingDocument.getNoKeyAttestationProofSpecification().getOrThrow()

            val outcome = with(issuer) {
                authorizedRequest.request(
                    requestPayload = pendingDocument.issuanceRequestPayload,
                    proofsSpecification = proofsSpecification,
                ).onSuccess {
                    authorizedRequest = it.first
                }.map {
                    it.second
                }
            }.getOrThrow()

            val result = when (outcome) {
                is SubmissionOutcome.Deferred -> {
                    // TODO store deferred context and outcome result
                    val deferredIssuanceContext = with(issuer) {
                        authorizedRequest.deferredContext(outcome)
                    }
                    val deferredContext: ByteArray = TODO()
                    documentManager.storeDeferredDocument(pendingDocument.unsignedDocument, deferredContext).kotlinResult
                }
                is SubmissionOutcome.Failed -> {
                    // clear up pending document
                    documentManager.deleteDocumentById(pendingDocument.unsignedDocument.id).kotlinResult
                }

                is SubmissionOutcome.Success -> {
                    documentManager.storeIssuedDocument(pendingDocument, outcome)
                }
            }
        }
    }
}