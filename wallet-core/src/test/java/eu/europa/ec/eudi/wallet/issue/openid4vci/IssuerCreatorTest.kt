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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vci.AuthorizationCodeDPoPBindingMethod
import eu.europa.ec.eudi.openid4vci.AuthorizationResponseIssChecking
import eu.europa.ec.eudi.openid4vci.CertificateChainTrust
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.DPoPUsage
import eu.europa.ec.eudi.openid4vci.EcConfig
import eu.europa.ec.eudi.openid4vci.EncryptionSupportConfig
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.JWKThumbprint
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.openid4vci.SupportedGrants
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.DPopConfig
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.SecureAreaDpopSigner
import eu.europa.ec.eudi.wallet.provider.WalletAttestationKey
import eu.europa.ec.eudi.wallet.provider.WalletKeyManager
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.mockk.CapturingSlot
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.isActive
import kotlinx.coroutines.test.runTest
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.net.URI
import java.net.URLDecoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import eu.europa.ec.eudi.openid4vci.DPoPConfig as VciDPoPConfig

class IssuerCreatorTest {

    private val config = OpenId4VciManager.Config(
        clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.None("client"),
        authFlowRedirectionURI = "app://redirect",
        dpopConfig = DPopConfig.Disabled,
    )

    private val requestedPaths = mutableListOf<String>()
    private val createdClients = mutableListOf<HttpClient>()

    /**
     * Wallet-initiated issuance and re-issuance fetch the issuer metadata again in the OpenID4VCI
     * library, so the library gets the configured policy also when issuer registration is disabled.
     */
    @Test
    fun `the configured metadata policy is passed to the library when issuer registration is disabled`() = runTest {
        val policy = IssuerMetadataPolicy.RequireSigned(issuerTrust = mockk<CertificateChainTrust>())
        val creator = IssuerCreator(
            context = mockk(relaxed = true),
            config = config,
            ktorHttpClientFactory = { mockk() },
            walletInstanceAttestationProvider = null,
            walletAttestationKeyManager = mockk(),
            logger = null,
            issuerMetadataPolicy = policy,
            issuerRegistrationEnabled = false,
        )

        val libraryConfig = with(creator) {
            config.toOpenId4VCIConfig(AuthorizationServerMetadata(Issuer("https://issuer.example")))
        }

        assertSame(policy, libraryConfig.issuerMetadataPolicy)
    }

    @Test
    fun `wallet-initiated issuance by configuration id fetches each metadata document once`() = runTest {
        val creator = issuerCreator()

        creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))

        assertEquals(1, requestCount(ISSUER_WELL_KNOWN_PATH), "issuer metadata requests: $requestedPaths")
        assertEquals(1, requestCount(AUTHORIZATION_SERVER_WELL_KNOWN_PATH), "authorization server requests: $requestedPaths")
    }

    @Test
    fun `wallet-initiated issuance by format fetches the issuer metadata once more to select the configuration`() = runTest {
        val creator = issuerCreator()

        creator.createIssuer(CREDENTIAL_ISSUER, MsoMdocFormat(MDL_DOCTYPE))

        assertEquals(2, requestCount(ISSUER_WELL_KNOWN_PATH), "issuer metadata requests: $requestedPaths")
        assertEquals(1, requestCount(AUTHORIZATION_SERVER_WELL_KNOWN_PATH), "authorization server requests: $requestedPaths")
    }

    @Test
    fun `attestation key is derived from the authorization server issuer of the resolved offer`() = runTest {
        val keyAliasInput = slot<String>()
        val supportedAlgorithms = slot<List<Algorithm>>()
        val creator = issuerCreator(
            clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
            walletAttestationKeyManager = walletAttestationKeyManager(keyAliasInput, supportedAlgorithms),
        )

        val creation = creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))

        assertEquals(AUTHORIZATION_SERVER, keyAliasInput.captured)
        assertEquals(listOf(Algorithm.fromJoseAlgorithmIdentifier("ES256")), supportedAlgorithms.captured)
        assertIs<ClientAuthentication.AttestationBased>(creator.clientAuthentication)
        assertEquals(ATTESTATION_KEY_ALIAS, creation.clientAttestationPopKeyId)
        assertEquals(1, requestCount(ISSUER_WELL_KNOWN_PATH), "issuer metadata requests: $requestedPaths")
        assertEquals(1, requestCount(AUTHORIZATION_SERVER_WELL_KNOWN_PATH), "authorization server requests: $requestedPaths")
        assertTrue(createdClients.single().isActive, "the issuer keeps using the http client")
    }

    @Test
    fun `the alias of the client attestation key is returned for an offer`() = runTest {
        val creator = issuerCreator(
            clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
            walletAttestationKeyManager = walletAttestationKeyManager(),
        )
        val offer = Offer(
            creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
                .issuer.credentialOffer
        )

        val creation = creator.createIssuer(offer)

        assertEquals(ATTESTATION_KEY_ALIAS, creation.clientAttestationPopKeyId)
    }

    @Test
    fun `a stored client attestation key is used with the authorization server it was used with`() = runTest {
        val keyManager = keyManagerWithStoredKey(Algorithm.ESP256)
        val creator = issuerCreator(
            clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
            walletAttestationKeyManager = keyManager,
        )

        val creation = creator.createIssuer(
            CREDENTIAL_ISSUER,
            listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)),
            existingClientAttestationKey = StoredClientAttestationKey(STORED_KEY_ALIAS, AUTHORIZATION_SERVER),
        )

        assertEquals(STORED_KEY_ALIAS, creation.clientAttestationPopKeyId)
        coVerify(exactly = 0) { keyManager.getOrCreateWalletAttestationKey(any(), any()) }
    }

    @Test
    fun `the key of the authorization server is used when the stored client attestation key does not fit`() = runTest {
        listOf(
            // Used with another authorization server
            keyManagerWithStoredKey(Algorithm.ESP256) to StoredClientAttestationKey(STORED_KEY_ALIAS, "https://other.example.com"),
            // No longer exists
            keyManagerWithStoredKey(null) to StoredClientAttestationKey(STORED_KEY_ALIAS, AUTHORIZATION_SERVER),
            // Has an algorithm the authorization server does not accept
            keyManagerWithStoredKey(Algorithm.ESP384) to StoredClientAttestationKey(STORED_KEY_ALIAS, AUTHORIZATION_SERVER),
            // Is not the key that earlier versions created for the authorization server
            keyManagerWithStoredKey(Algorithm.ESP256, OTHER_KEY_ALIAS) to
                StoredClientAttestationKey(OTHER_KEY_ALIAS, AUTHORIZATION_SERVER),
        ).forEach { (keyManager, storedKey) ->
            val creator = issuerCreator(
                clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
                walletAttestationKeyManager = keyManager,
            )

            val creation = creator.createIssuer(
                CREDENTIAL_ISSUER,
                listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)),
                existingClientAttestationKey = storedKey,
            )

            assertEquals(ATTESTATION_KEY_ALIAS, creation.clientAttestationPopKeyId, storedKey.toString())
        }
    }

    @Test
    fun `the http client is closed when the client authentication cannot be built`() = runTest {
        val creator = issuerCreator(
            clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
            authorizationServerMetadata = authorizationServerMetadata(advertisesClientAttestation = false),
        )

        assertFails {
            creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
        }

        assertFalse(createdClients.single().isActive)
    }

    /**
     * The client authentication passed to [eu.europa.ec.eudi.openid4vci.Issuer.make] must be the one
     * built from the resolved offer, not the placeholder used to resolve it. Only an attestation-based
     * client authentication is checked against the client attestation algorithms the authorization
     * server advertises, so with the placeholder issuer creation would succeed.
     */
    @Test
    fun `Issuer make receives the client authentication built from the resolved offer`() = runTest {
        val creator = issuerCreator(
            clientAuthenticationType = OpenId4VciManager.ClientAuthenticationType.AttestationBased("client"),
            walletAttestationKeyManager = walletAttestationKeyManager(),
            authorizationServerMetadata = authorizationServerMetadata(
                advertisesClientAttestation = true,
                clientAttestationSigningAlgorithm = "ES384",
            ),
        )

        val error = assertFails {
            creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
        }

        assertTrue(
            error.message.orEmpty().contains("Client Attestation JWS Algorithm not supported"),
            "unexpected failure: $error",
        )
    }

    @Test
    fun `metadata resolution errors are rethrown as reported by the metadata resolver`() = runTest {
        val creator = issuerCreator(issuerMetadataAvailable = false)

        val error = assertFails {
            creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
        }

        assertIs<CredentialIssuerMetadataError>(error)
        assertFalse(createdClients.single().isActive)
    }

    @Test
    fun `the authorization code grant options are passed to the library with both grants`() = runTest {
        val grants = config.toSupportedGrants()

        assertIs<SupportedGrants.Both>(grants)
        with(grants.authorizationCode) {
            assertEquals(URI.create("app://redirect"), authFlowRedirectionURI)
            assertEquals(ParUsage.IfSupported, parUsage)
            assertEquals(AuthorizationResponseIssChecking.IfSupported, authResponseIssChecking)
            assertEquals(AuthorizationCodeDPoPBindingMethod.DPoPHeader, authorizationCodeDPoPBindingMethod)
        }
    }

    @Test
    fun `the configured iss checking policy and binding method are passed to the library`() = runTest {
        val grants = config.copy(
            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
            authorizationCodeDPoPBinding = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
        ).toSupportedGrants()

        assertEquals(AuthorizationResponseIssChecking.Never, grants.authorizationCode.authResponseIssChecking)
        assertEquals(
            AuthorizationCodeDPoPBindingMethod.DPoPJkt,
            grants.authorizationCode.authorizationCodeDPoPBindingMethod,
        )
    }

    @Test
    fun `the PAR usage is mapped to the library PAR usage`() = runTest {
        mapOf(
            OpenId4VciManager.Config.ParUsage.IF_SUPPORTED to ParUsage.IfSupported,
            OpenId4VciManager.Config.ParUsage.REQUIRED to ParUsage.Required,
            OpenId4VciManager.Config.ParUsage.NEVER to ParUsage.Never,
            // Not one of the defined values
            99 to ParUsage.IfSupported,
        ).forEach { (parUsage, expected) ->
            assertEquals(
                expected,
                config.copy(parUsage = parUsage).toSupportedGrants().authorizationCode.parUsage,
                "parUsage $parUsage",
            )
        }
    }

    @Test
    fun `the library config supports both grants`() = runTest {
        val creator = IssuerCreator(
            context = mockk(relaxed = true),
            config = config,
            ktorHttpClientFactory = { mockk() },
            walletInstanceAttestationProvider = null,
            walletAttestationKeyManager = mockk(),
            logger = null,
        )

        val libraryConfig = with(creator) { config.toOpenId4VCIConfig(authorizationServerMetadata = null) }

        assertEquals(config.toSupportedGrants(), libraryConfig.grants)
    }

    @Test
    fun `the DPoP signer is provisioned with the thumbprint of a new DPoP key`() = runTest {
        val dpopConfig = softwareDPopConfig()
        val creator = IssuerCreator(
            context = mockk(relaxed = true),
            config = config.copy(dpopConfig = dpopConfig),
            ktorHttpClientFactory = { mockk() },
            walletInstanceAttestationProvider = null,
            walletAttestationKeyManager = mockk(),
            logger = null,
        )

        val libraryConfig = with(creator) {
            config.copy(dpopConfig = dpopConfig).toOpenId4VCIConfig(authorizationServerMetadata = null)
        }
        val (signer, thumbprint) = provisionDPoPSigner(libraryConfig.dPoPUsage)

        assertEquals(signer.acquire().publicMaterial.computeThumbprint().toString(), thumbprint)
        val keyAlias = assertNotNull(creator.dpopKeyAlias)
        assertEquals(SecureAreaDpopSigner.fromExistingKey(dpopConfig, keyAlias).jwkThumbprint(), thumbprint)
    }

    @Test
    fun `the DPoP signer is provisioned with the thumbprint of an existing DPoP key`() = runTest {
        val dpopConfig = softwareDPopConfig()
        val existingKey = SecureAreaDpopSigner(dpopConfig, listOf(Algorithm.ESP256))
        val creator = IssuerCreator(
            context = mockk(relaxed = true),
            config = config.copy(dpopConfig = dpopConfig),
            ktorHttpClientFactory = { mockk() },
            walletInstanceAttestationProvider = null,
            walletAttestationKeyManager = mockk(),
            logger = null,
        )

        val libraryConfig = with(creator) {
            config.copy(dpopConfig = dpopConfig).toOpenId4VCIConfig(
                authorizationServerMetadata = null,
                existingDpopKeyAlias = existingKey.keyInfo.alias,
            )
        }
        val (_, thumbprint) = provisionDPoPSigner(libraryConfig.dPoPUsage)

        assertEquals(existingKey.jwkThumbprint(), thumbprint)
    }

    /**
     * Without PAR the DPoP header cannot be sent, so the library binds the authorization code with the
     * `dpop_jkt` parameter of the authorization request, which needs the thumbprint of the DPoP key.
     */
    @Test
    fun `without PAR the authorization request binds the authorization code to the DPoP key with dpop_jkt`() = runTest {
        val dpopConfig = softwareDPopConfig()
        val creator = issuerCreator(
            authorizationServerMetadata = authorizationServerMetadata(
                advertisesClientAttestation = false,
                additionalMembers = DPOP_SUPPORTED,
            ),
        ) { copy(dpopConfig = dpopConfig) }
        val issuer = creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
            .issuer

        val authorizationUrl = issuer.prepareAuthorizationRequest().getOrThrow().authorizationCodeURL.value.toURI()

        val keyAlias = assertNotNull(creator.dpopKeyAlias)
        assertEquals(
            SecureAreaDpopSigner.fromExistingKey(dpopConfig, keyAlias).jwkThumbprint(),
            queryParameters(authorizationUrl)["dpop_jkt"],
        )
    }

    @Test
    fun `without binding the authorization request has no dpop_jkt`() = runTest {
        val dpopConfig = softwareDPopConfig()
        val creator = issuerCreator(
            authorizationServerMetadata = authorizationServerMetadata(
                advertisesClientAttestation = false,
                additionalMembers = DPOP_SUPPORTED,
            ),
        ) {
            copy(
                dpopConfig = dpopConfig,
                authorizationCodeDPoPBinding = AuthorizationCodeDPoPBindingMethod.None,
            )
        }
        val issuer = creator.createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
            .issuer

        val authorizationUrl = issuer.prepareAuthorizationRequest().getOrThrow().authorizationCodeURL.value.toURI()

        assertNull(queryParameters(authorizationUrl)["dpop_jkt"])
    }

    @Test
    fun `authorization fails when the authorization server advertises iss and the response has none`() = runTest {
        val issuer = issuerAdvertisingIss()

        val error = assertFails {
            IssuerAuthorization(authorizationHandler(issuer = null)).authorize(issuer, txCode = null)
        }

        assertIs<CredentialIssuanceError.MissingAuthorizationResponseIssuer>(error)
        assertFalse(requestedPaths.contains(TOKEN_PATH), "token requested: $requestedPaths")
    }

    @Test
    fun `authorization fails when the iss of the response is not the authorization server`() = runTest {
        val issuer = issuerAdvertisingIss()

        val error = assertFails {
            IssuerAuthorization(authorizationHandler(issuer = "https://other.example.com"))
                .authorize(issuer, txCode = null)
        }

        assertIs<CredentialIssuanceError.InvalidAuthorizationIssuer>(error)
        assertFalse(requestedPaths.contains(TOKEN_PATH), "token requested: $requestedPaths")
    }

    @Test
    fun `the access token is requested when the iss of the response is the authorization server`() = runTest {
        val issuer = issuerAdvertisingIss()

        // The mock engine has no token endpoint, so the token request itself fails
        assertFails {
            IssuerAuthorization(authorizationHandler(issuer = AUTHORIZATION_SERVER)).authorize(issuer, txCode = null)
        }

        assertTrue(requestedPaths.contains(TOKEN_PATH), "token not requested: $requestedPaths")
    }

    @Test
    fun `the access token is requested without iss when iss checking is disabled`() = runTest {
        val issuer = issuerAdvertisingIss(AuthorizationResponseIssChecking.Never)

        // The mock engine has no token endpoint, so the token request itself fails
        assertFails {
            IssuerAuthorization(authorizationHandler(issuer = null)).authorize(issuer, txCode = null)
        }

        assertTrue(requestedPaths.contains(TOKEN_PATH), "token not requested: $requestedPaths")
    }

    /** An issuer whose authorization server advertises the `iss` parameter of the authorization response. */
    private suspend fun issuerAdvertisingIss(
        authResponseIssChecking: AuthorizationResponseIssChecking = AuthorizationResponseIssChecking.IfSupported,
    ): eu.europa.ec.eudi.openid4vci.Issuer =
        issuerCreator(
            authorizationServerMetadata = authorizationServerMetadata(
                advertisesClientAttestation = false,
                additionalMembers = ISS_SUPPORTED,
            ),
        ) { copy(authResponseIssChecking = authResponseIssChecking) }
            .createIssuer(CREDENTIAL_ISSUER, listOf(CredentialConfigurationIdentifier(MDL_CONFIGURATION_ID)))
            .issuer

    /**
     * An [AuthorizationHandler] that authorizes at once, returning the state of the authorization
     * request and the given [issuer].
     */
    private fun authorizationHandler(issuer: String?) = AuthorizationHandler { authorizationUrl ->
        val state = queryParameters(URI(authorizationUrl)).getValue("state")
        Result.success(AuthorizationResponse("code", state, issuer))
    }

    private fun queryParameters(uri: URI): Map<String, String> =
        uri.rawQuery.split("&").associate { parameter ->
            val (name, value) = parameter.split("=", limit = 2)
            URLDecoder.decode(name, "UTF-8") to URLDecoder.decode(value, "UTF-8")
        }

    private suspend fun softwareDPopConfig() = DPopConfig.Custom(
        secureArea = SoftwareSecureArea.create(EphemeralStorage()),
        createKeySettingsBuilder = { algorithms ->
            SoftwareCreateKeySettings.Builder()
                .setAlgorithm(algorithms.first())
                .build()
        },
    )

    private suspend fun provisionDPoPSigner(dPoPUsage: DPoPUsage<VciDPoPConfig>): Pair<Signer<JWK>, JWKThumbprint?> {
        val dPoPConfig = assertIs<DPoPUsage.IfSupported<*>>(dPoPUsage).value as VciDPoPConfig
        return dPoPConfig.provisionDPoPSigner(HttpsUrl(AUTHORIZATION_SERVER).getOrThrow())
    }

    /**
     * A [WalletKeyManager] that returns an ES256 attestation key, capturing the alias input and the
     * algorithms it is asked for.
     */
    private fun walletAttestationKeyManager(
        keyAliasInput: CapturingSlot<String> = slot(),
        supportedAlgorithms: CapturingSlot<List<Algorithm>> = slot(),
    ): WalletKeyManager {
        val keyInfo = mockk<KeyInfo> {
            every { algorithm } returns Algorithm.ESP256
            every { alias } returns ATTESTATION_KEY_ALIAS
        }
        return mockk {
            coEvery {
                getOrCreateWalletAttestationKey(capture(keyAliasInput), capture(supportedAlgorithms))
            } returns Result.success(WalletAttestationKey(keyInfo) { it })
        }
    }

    /**
     * A [WalletKeyManager] with a stored key [storedKeyAlias] of [storedKeyAlgorithm], or without it
     * when null, and the key [ATTESTATION_KEY_ALIAS] of the authorization server.
     */
    private fun keyManagerWithStoredKey(
        storedKeyAlgorithm: Algorithm?,
        storedKeyAlias: String = STORED_KEY_ALIAS,
    ): WalletKeyManager = mockk {
        coEvery { getWalletAttestationKey(storedKeyAlias) } returns
            storedKeyAlgorithm?.let { attestationKey(storedKeyAlias, it) }
        coEvery { getOrCreateWalletAttestationKey(AUTHORIZATION_SERVER, any()) } returns
            Result.success(attestationKey(ATTESTATION_KEY_ALIAS, Algorithm.ESP256))
    }

    private fun attestationKey(keyAlias: String, keyAlgorithm: Algorithm): WalletAttestationKey {
        val keyInfo = mockk<KeyInfo> {
            every { algorithm } returns keyAlgorithm
            every { alias } returns keyAlias
        }
        return WalletAttestationKey(keyInfo) { it }
    }

    /** Number of requests made to the given well-known metadata path. */
    private fun requestCount(wellKnownPath: String): Int =
        requestedPaths.count { it.startsWith(wellKnownPath) }

    /**
     * Creates an [IssuerCreator] whose http clients serve the credential issuer and authorization
     * server metadata from a mock engine, recording every requested path and created client.
     */
    private fun issuerCreator(
        clientAuthenticationType: OpenId4VciManager.ClientAuthenticationType =
            OpenId4VciManager.ClientAuthenticationType.None("client"),
        walletAttestationKeyManager: WalletKeyManager = mockk(),
        authorizationServerMetadata: String = authorizationServerMetadata(advertisesClientAttestation = true),
        issuerMetadataAvailable: Boolean = true,
        configure: OpenId4VciManager.Config.() -> OpenId4VciManager.Config = { this },
    ): IssuerCreator {
        val jsonHeaders = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        val engine = MockEngine { request ->
            val path = request.url.encodedPath
            requestedPaths += path
            when {
                path.startsWith(ISSUER_WELL_KNOWN_PATH) && issuerMetadataAvailable ->
                    respond(ISSUER_METADATA, HttpStatusCode.OK, jsonHeaders)

                path.startsWith(AUTHORIZATION_SERVER_WELL_KNOWN_PATH) ->
                    respond(authorizationServerMetadata, HttpStatusCode.OK, jsonHeaders)

                else -> respondError(HttpStatusCode.NotFound)
            }
        }
        return IssuerCreator(
            context = mockk(relaxed = true),
            config = OpenId4VciManager.Config(
                clientAuthenticationType = clientAuthenticationType,
                authFlowRedirectionURI = "app://redirect",
                dpopConfig = DPopConfig.Disabled,
                responseEncryptionConfig = EncryptionSupportConfig(
                    credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
                    ecConfig = EcConfig(ecKeyCurve = Curve.P_256),
                    rsaConfig = null,
                ),
            ).configure(),
            ktorHttpClientFactory = { HttpClient(engine).also { createdClients += it } },
            walletInstanceAttestationProvider = mockk(relaxed = true),
            walletAttestationKeyManager = walletAttestationKeyManager,
            logger = null,
        )
    }

    private companion object {
        const val CREDENTIAL_ISSUER = "https://issuer.example.com"
        const val AUTHORIZATION_SERVER = "https://auth.example.com/realms/test"
        const val ISSUER_WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer"
        const val AUTHORIZATION_SERVER_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"
        const val MDL_CONFIGURATION_ID = "org.iso.18013.5.1.mDL"
        const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
        const val ATTESTATION_KEY_ALIAS = "client-attestation-test"
        // The alias that earlier versions gave to the key of AUTHORIZATION_SERVER: 16 hexadecimal digits of its SHA-256
        const val STORED_KEY_ALIAS = "client-attestation-0bd1f0af3110b498"
        const val OTHER_KEY_ALIAS = "client-attestation-other"
        const val TOKEN_PATH = "/realms/test/token"
        const val DPOP_SUPPORTED = """"dpop_signing_alg_values_supported": ["ES256"],"""
        const val ISS_SUPPORTED = """"authorization_response_iss_parameter_supported": true,"""

        val ISSUER_METADATA = """
            {
              "credential_issuer": "$CREDENTIAL_ISSUER",
              "authorization_servers": ["$AUTHORIZATION_SERVER"],
              "credential_endpoint": "$CREDENTIAL_ISSUER/credential",
              "credential_configurations_supported": {
                "$MDL_CONFIGURATION_ID": {
                  "format": "mso_mdoc",
                  "scope": "mdl",
                  "doctype": "$MDL_DOCTYPE"
                }
              }
            }
        """.trimIndent()

        /**
         * Authorization server metadata, optionally advertising attestation-based client
         * authentication with ES256 proofs of possession and the given client attestation algorithm,
         * followed by [additionalMembers], each ending with a comma.
         */
        fun authorizationServerMetadata(
            advertisesClientAttestation: Boolean,
            clientAttestationSigningAlgorithm: String = "ES256",
            additionalMembers: String = "",
        ): String {
            val clientAttestation = if (advertisesClientAttestation) {
                """
                  "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
                  "client_attestation_signing_alg_values_supported": ["$clientAttestationSigningAlgorithm"],
                  "client_attestation_pop_signing_alg_values_supported": ["ES256"],
                """
            } else ""
            return """
                {
                  $clientAttestation
                  $additionalMembers
                  "issuer": "$AUTHORIZATION_SERVER",
                  "authorization_endpoint": "$AUTHORIZATION_SERVER/authorize",
                  "token_endpoint": "$AUTHORIZATION_SERVER/token",
                  "response_types_supported": ["code"]
                }
            """.trimIndent()
        }
    }
}
