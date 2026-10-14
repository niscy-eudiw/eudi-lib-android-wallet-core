/*
 * Copyright (c) 2025-2026 European Commission
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

package eu.europa.ec.eudi.iso18013.transfer.internal

import eu.europa.ec.eudi.iso18013.transfer.response.ReaderAuthPolicy
import org.multipaz.cose.Cose
import org.multipaz.cose.toCoseLabel
import org.multipaz.crypto.javaX509Certificates
import org.multipaz.mdoc.request.DocRequest

/**
 * Evaluates whether a single [DocRequest] passes the configured [ReaderAuthPolicy]
 * based on its own per-DocRequest `readerAuth` signature.
 *
 * This is used when the request uses per-DocRequest signatures (ISO 18013-5 1st edition),
 * **not** when `readerAuthAll` (2nd edition) covers all DocRequests globally.
 *
 * The logic mirrors the global policy gate in `ProcessedDeviceRequest.generateResponse()`,
 * but scoped to the individual DocRequest's certificate chain:
 *
 *  - [ReaderAuthPolicy.DoNotEnforce]: always passes.
 *  - [ReaderAuthPolicy.EnforceIfPresent]: passes when `readerAuth` is absent (nothing to enforce)
 *    or when the cert chain validates against the trust store. Fails when `readerAuth` is present
 *    but the chain is untrusted.
 *  - [ReaderAuthPolicy.AlwaysRequire]: passes only when `readerAuth` is present **and** the
 *    cert chain validates against the trust store.
 *
 * The cert chain extraction first looks in the protected header, otherwise falls back to
 * the unprotected header.
 *
 * @receiver the [DocRequest] whose `readerAuth` is evaluated. Must only be called after
 *   `DeviceRequest.verifyReaderAuthentication()` has been invoked (otherwise accessing
 *   `readerAuth` throws).
 * @param policy the active [ReaderAuthPolicy].
 * @return `true` if this DocRequest is allowed through; `false` if the policy rejects it.
 */
internal fun DocRequest.passesReaderAuthPolicy(policy: ReaderAuthPolicy): Boolean {
    if (policy is ReaderAuthPolicy.DoNotEnforce) return true

    val coseSign1 = readerAuth ?: // No per-DocRequest reader auth on this DocRequest.
    return when (policy) {
        is ReaderAuthPolicy.EnforceIfPresent -> true   // nothing to enforce
        is ReaderAuthPolicy.AlwaysRequire -> false      // auth is mandatory
        else -> true
    }

    // readerAuth is present — extract the cert chain and validate trust.
    val trustStore = policy.readerTrustStore ?: return false
    val certChainDataItem = coseSign1.protectedHeaders[Cose.COSE_LABEL_X5CHAIN.toCoseLabel]
        ?: coseSign1.unprotectedHeaders[Cose.COSE_LABEL_X5CHAIN.toCoseLabel]
        ?: return false
    val javaCerts = certChainDataItem.asX509CertChain.javaX509Certificates
    if (javaCerts.isEmpty()) return false

    return trustStore.validateCertificationTrustPath(javaCerts)
}
