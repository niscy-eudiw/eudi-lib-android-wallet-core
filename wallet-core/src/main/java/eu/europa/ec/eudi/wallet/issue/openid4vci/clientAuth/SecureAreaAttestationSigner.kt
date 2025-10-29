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

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.wallet.issue.openid4vci.javaAlgorithm
import eu.europa.ec.eudi.wallet.logging.Logger
import kotlinx.coroutines.runBlocking
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.SecureArea

/**
 * Internal signer implementation that uses a SecureArea key for attestation-based authentication.
 *
 * This signer retrieves the attestation key from the SecureArea and uses it for signing
 * proof-of-possession (PoP) tokens during the OpenID4VCI credential issuance flow.
 *
 * @property secureArea The secure area containing the attestation key
 * @property keyAlias The alias of the attestation key in the secure area
 * @property unlockKey Function to provide unlock data if the key requires authentication
 * @property logger Optional logger for debugging and error reporting
 */
internal class SecureAreaAttestationSigner(
    private val secureArea: SecureArea,
    private val keyAlias: String,
    private val unlockKey: suspend (keyAlias: String, secureArea: SecureArea) -> KeyUnlockData? = { _, _ -> null },
    private val logger: Logger?,
) : Signer<JWK> {

    private val keyInfo = runBlocking {
        secureArea.getKeyInfo(keyAlias)
    }

    override val javaAlgorithm: String = keyInfo.algorithm.javaAlgorithm
        ?: throw IllegalArgumentException("Unsupported algorithm: ${keyInfo.algorithm}")

    /**
     * Acquires a signing operation with the attestation key.
     *
     * @return [SignOperation] containing the signing function and public key as JWK
     * @throws Exception if key retrieval or JWK conversion fails
     */
    override suspend fun acquire(): SignOperation<JWK> {
        try {
            // Get the key info from SecureArea
            val publicKey = keyInfo.publicKey

            // Convert to JWK format
            val jwk = JWK.parse(publicKey.toJwk().toString())

            // For AndroidKeystoreSecureArea, we can use the Crypto utilities to sign
            return SignOperation(
                function = { input ->
                    secureArea.sign(keyAlias, input, unlockKey(keyAlias, secureArea)).toDerEncoded()
                },
                publicMaterial = jwk
            )
        } catch (e: Exception) {
            logger?.log(
                Logger.Record(
                    level = Logger.Companion.LEVEL_ERROR,
                    message = "Error acquiring sign operation for attestation",
                    thrown = e
                )
            )
            throw e
        }
    }

    /**
     * Releases the signing operation resources.
     *
     * For SecureArea-based signing, no resources need to be released.
     *
     * @param signOperation The signing operation to release (unused)
     */
    override suspend fun release(signOperation: SignOperation<JWK>?) {
        // Nothing to release
    }
}

