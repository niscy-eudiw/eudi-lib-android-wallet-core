/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci.clientAuth

import android.content.Context
import eu.europa.ec.eudi.wallet.issue.openid4vci.clientAuth.ClientAttestationConfig.Companion.default
import kotlinx.io.bytestring.ByteString
import org.multipaz.context.initializeApplication
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.AndroidKeystoreCreateKeySettings
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UserAuthenticationType
import org.multipaz.storage.android.AndroidStorage
import java.security.SecureRandom
import kotlin.time.Duration


fun interface CreateKeySettingsBuilder {
    suspend fun build(
        clientAttestationPOPJWSAlgs: List<Algorithm>?,
        challenge: String?
    ): CreateKeySettings
}

/**
 * Configuration for attestation-based client authentication in OpenID4VCI flows.
 *
 * Attestation-based authentication provides a more secure alternative to traditional OAuth2 client
 * authentication by using cryptographic proof of the client's identity. This is particularly important
 * for mobile wallets where traditional client secrets cannot be securely stored.
 *
 * ## Authentication Flow
 * When using attestation-based authentication, the library performs the following steps:
 * 1. Creates a key pair in the [secureArea] using the provided [challenge] (if any)
 * 2. Extracts the public key and invokes [jwtProvider] to obtain an attestation JWT
 * 3. Uses the returned attestation JWT for client authentication with the issuer
 * 4. Signs proof-of-possession (PoP) tokens using the created private key
 *
 * ## Usage Example
 * ```kotlin
 * // Using the default factory method (recommended)
 * val config = ClientAttestationConfig.default(
 *     context = applicationContext,
 *     jwtProvider = object : ClientAttestationJwtProvider {
 *         override suspend fun provide(publicKey: JsonObject): String {
 *             // Communicate with your wallet provider backend
 *             return walletProviderService.getAttestationJwt(publicKey)
 *         }
 *     },
 *     challenge = issuerChallenge // from issuer metadata or authorization server
 * )
 *
 * // Or create with custom settings
 * val customConfig = ClientAttestationConfig(
 *     jwtProvider = myJwtProvider,
 *     challenge = "custom-challenge",
 *     secureArea = customSecureArea,
 *     createKeySettingsBuilder = { challenge ->
 *         AndroidKeystoreCreateKeySettings.Builder(ByteString(challenge?.toByteArray() ?: byteArrayOf()))
 *             .setAlgorithm(Algorithm.ESP256)
 *             .build()
 *     }
 * )
 *
 * // Use in OpenId4VciManager configuration
 * val vciConfig = OpenId4VciManager.Config {
 *     withIssuerUrl("https://issuer.example.com")
 *     withAuthFlowRedirectionURI("eudi-wallet://callback")
 *     withClientAttestation(config)
 * }
 * ```
 *
 * @property jwtProvider Provider that communicates with the wallet provider backend to obtain attestation JWT.
 *                       The provider receives the public key and must return a valid attestation JWT.
 * @property challenge Optional challenge from the credential issuer or authorization server.
 *                     Used during key creation for hardware-backed attestation. If null, a random
 *                     challenge will be generated when using the default factory method.
 * @property secureArea The [SecureArea] implementation for secure key storage and operations.
 *                      Typically uses [AndroidKeystoreSecureArea] for hardware-backed security.
 * @property createKeySettingsBuilder Suspending function that creates [CreateKeySettings] for key pair generation.
 *                                    Receives the challenge and should return appropriate settings for the secure area.
 * @property unlockKey Optional suspending function to provide [KeyUnlockData] when the key requires unlocking
 *                     (e.g., for biometric or PIN authentication). Defaults to returning null (no unlock needed).
 *
 * @see [ClientAttestationJwtProvider] for implementing the JWT provider
 * @see [AndroidKeystoreSecureArea] for hardware-backed secure storage
 * @see [default] for creating instances with recommended defaults
 */
data class ClientAttestationConfig(
    val jwtProvider: ClientAttestationJwtProvider,
    val challenge: String?,
    val secureArea: SecureArea,
    val createKeySettingsBuilder: CreateKeySettingsBuilder,
    val unlockKey: suspend (keyAlias: String, secureArea: SecureArea) -> KeyUnlockData? = { _, _ -> null },
) {
    companion object {
        /**
         * Creates a default [ClientAttestationConfig] using [AndroidKeystoreSecureArea].
         *
         * This factory method provides a convenient way to create attestation configuration with
         * secure defaults that work for most use cases. It automatically configures:
         *
         * ## Default Configuration
         * - **Secure Storage**: Dedicated database at `{noBackupFilesDir}/client-attestation.db`
         * - **Secure Area**: Android Keystore with StrongBox support when available
         * - **Algorithm**: ES256 (ECDSA with P-256 curve and SHA-256)
         * - **Challenge**: Uses provided challenge, or generates random 16-byte challenge if null
         * - **User Authentication**: Disabled for automatic operation (no biometric/PIN required)
         * - **Hardware Security**: StrongBox enabled on supported devices for enhanced security
         *
         * ## Usage Example
         * ```kotlin
         * // Basic usage with custom JWT provider
         * val config = ClientAttestationConfig.default(
         *     context = applicationContext,
         *     jwtProvider = object : ClientAttestationJwtProvider {
         *         override suspend fun provide(publicKey: JsonObject): String {
         *             // Call your backend service
         *             return httpClient.post("https://wallet-provider.example.com/attestation") {
         *                 setBody(publicKey)
         *             }.body<String>()
         *         }
         *     },
         *     challenge = issuerMetadata.challenge // Optional
         * )
         *
         * // Use with OpenId4VciManager
         * val vciManager = OpenId4VciManager(context) {
         *     config = OpenId4VciManager.Config {
         *         withIssuerUrl("https://issuer.example.com")
         *         withAuthFlowRedirectionURI("eudi-wallet://callback")
         *         withClientAttestation(config) // Use attestation instead of clientId
         *     }
         *     documentManager = eudiWallet.documentManager
         * }
         * ```
         *
         * ## Security Considerations
         * - The secure area is created in the no-backup directory to prevent cloud backup
         * - Keys are stored in Android Keystore, protected by hardware security when available
         * - StrongBox (dedicated security chip) is used automatically on supported devices
         * - Each key creation includes attestation data proving the key's secure properties
         *
         * @param context Android context, used for accessing no-backup storage directory
         * @param jwtProvider Your implementation that communicates with the wallet provider backend
         *                    to exchange the public key for an attestation JWT
         * @param challenge Optional challenge from the credential issuer or authorization server.
         *                  Used for hardware attestation. If null, a random 16-byte challenge is generated.
         *
         * @return A [ClientAttestationConfig] configured with Android Keystore-backed secure area
         *         and recommended security settings
         *
         * @see [ClientAttestationJwtProvider] for implementing the JWT provider interface
         * @see [AndroidKeystoreSecureArea] for details on hardware-backed key storage
         * @see [AndroidKeystoreCreateKeySettings] for key creation settings
         */
        @JvmStatic
        suspend fun default(
            context: Context,
            jwtProvider: ClientAttestationJwtProvider,
            challenge: String? = null,
        ): ClientAttestationConfig {
            // Create a dedicated storage for client attestation keys
            val storage = AndroidStorage(
                context.noBackupFilesDir.absolutePath + "/client-attestation.db"
            )

            // Create AndroidKeystoreSecureArea using the factory method
            val secureArea = AndroidKeystoreSecureArea.create(storage)

            return ClientAttestationConfig(
                jwtProvider = jwtProvider,
                challenge = challenge,
                secureArea = secureArea,
                createKeySettingsBuilder = { popJwsAlgs, challenge ->
                    initializeApplication(context)
                    val capabilities = AndroidKeystoreSecureArea.Capabilities()
                    val challengeBytes = challenge?.toByteArray() ?: ByteArray(16).apply {
                        SecureRandom().nextBytes(this)
                    }
                    val supportedAlgorithms = secureArea.supportedAlgorithms
                        .filter { it.isSigning }
                        .associateBy { it.joseAlgorithmIdentifier }


                    check(popJwsAlgs.isNullOrEmpty().not()) {
                        "Authorization server metadata does not contain any algorithms for client attestation"
                    }

                    val matchedAlgorithm = popJwsAlgs
                        .firstNotNullOfOrNull { jwsAlg ->
                            supportedAlgorithms[jwsAlg.joseAlgorithmIdentifier]
                        }
                        ?: throw IllegalStateException(
                            "No supported algorithm found for DPoP. Server algorithms: $popJwsAlgs, " +
                                    "supported algorithms: ${supportedAlgorithms.keys}"
                        )

                    AndroidKeystoreCreateKeySettings.Builder(ByteString(challengeBytes))
                        .setAlgorithm(matchedAlgorithm)
                        .setUseStrongBox(capabilities.strongBoxSupported)
                        .setUserAuthenticationRequired(
                            required = false,
                            timeout = Duration.INFINITE,
                            userAuthenticationTypes = setOf(
                                UserAuthenticationType.BIOMETRIC, UserAuthenticationType.LSKF
                            )
                        )
                        .build()
                },
            )
        }
    }
}

