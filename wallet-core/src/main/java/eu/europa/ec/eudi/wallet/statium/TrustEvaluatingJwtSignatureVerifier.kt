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
package eu.europa.ec.eudi.wallet.statium

import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifier
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.statium.VerifyStatusListTokenJwtSignature
import eu.europa.ec.eudi.wallet.trust.StatusListTrustConfig
import eu.europa.ec.eudi.wallet.trust.TrustPolicy
import java.security.cert.X509Certificate
import kotlin.time.Instant

/**
 * Wraps a [VerifyStatusListTokenJwtSignature] to add ETSI trust evaluation of
 * the signer's certificate chain after cryptographic signature verification.
 *
 * @param delegate the underlying JWT signature verifier
 * @param trustConfig the ETSI trust configuration for status list tokens
 * @param attestationIdentifier the attestation identifier derived from the document format
 */
internal class TrustEvaluatingJwtSignatureVerifier(
    private val delegate: VerifyStatusListTokenJwtSignature,
    private val trustConfig: StatusListTrustConfig,
    private val attestationIdentifier: AttestationIdentifier,
) : VerifyStatusListTokenJwtSignature {

    override suspend fun invoke(
        statusListToken: String,
        at: Instant,
    ): Result<Unit> = runCatching {
        // 1. Delegate cryptographic signature verification
        delegate(statusListToken, at).getOrThrow()

        // 2. Extract x5c certificate chain from JWT header
        val certs = extractX5cFromJwt(statusListToken)

        // 3. Evaluate trust via ETSI
        val trustResult = trustConfig.isChainTrustedForAttestation
            .issuance(certs, attestationIdentifier)

        // 4. Resolve verification context from classifications
        val verificationContext = trustConfig.classifications
            ?.classify(attestationIdentifier)
            ?.fold(
                ifPid = VerificationContext.PID,
                ifPubEaa = VerificationContext.PubEAA,
                ifQEaa = VerificationContext.QEAA,
                ifEaa = { useCase -> VerificationContext.EAA(useCase) },
            )

        // 5. Apply policy
        val action = trustConfig.trustPolicy.resolve(attestationIdentifier, verificationContext)
        if (action == TrustPolicy.Action.ENFORCE && trustResult is CertificationChainValidation.NotTrusted) {
            throw StatusListNotTrustedException(trustResult.cause)
        }
    }

    companion object {
        private fun extractX5cFromJwt(statusListToken: String): List<X509Certificate> {
            val signedJwt = SignedJWT.parse(statusListToken)
            val x5cChain = signedJwt.header?.x509CertChain
                ?: throw IllegalStateException("Missing x5c in JWT header")
            return x5cChain.map { certBase64 ->
                X509CertUtils.parse(certBase64.decode())
                    ?: throw IllegalStateException("Failed to parse x5c certificate")
            }
        }
    }
}
