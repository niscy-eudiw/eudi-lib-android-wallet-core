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
package eu.europa.ec.eudi.wallet.registration.relyingparty

import eu.europa.ec.eudi.openid4vp.Format
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.metaMsoMdoc
import eu.europa.ec.eudi.openid4vp.dcql.metaSdJwtVc
import eu.europa.ec.eudi.wallet.registration.credentialMetaOrNull
import eu.europa.ec.eudi.wallet.registration.ClaimPathElement as RegistrationClaimPathElement

/**
 * Projects the credential queries of a DCQL query onto the requested attestations checked against the
 * registered scope.
 *
 * The `vct_values` of an SD-JWT VC query are alternative types and a credential of any of them can be
 * presented (OpenID4VP 1.0 Appendix B.3.5), so each type is a requested attestation of its own.
 */
internal fun DCQL.toRequestedAttestations(): List<RequestedAttestation> =
    credentials.value.flatMap { it.toRequestedAttestations() }

private fun CredentialQuery.toRequestedAttestations(): List<RequestedAttestation> {
    val claimPaths = claims.orEmpty().map { claimsQuery ->
        claimsQuery.path.value.map { it.toRegistrationClaimPathElement() }
    }
    val docType = if (format == Format.MsoMdoc) metaMsoMdoc?.doctypeValue?.value else null
    val vctValues = if (format == Format.SdJwtVc) metaSdJwtVc?.vctValues else null
    if (vctValues.isNullOrEmpty()) {
        return listOf(
            RequestedAttestation(
                format = format.value,
                meta = credentialMetaOrNull(doctypeValue = docType),
                claimPaths = claimPaths,
            ),
        )
    }
    return vctValues.distinct().map { vct ->
        RequestedAttestation(
            format = format.value,
            meta = credentialMetaOrNull(vctValues = listOf(vct)),
            claimPaths = claimPaths,
        )
    }
}

/** Projects a DCQL claim path element onto its registration equivalent, element for element. */
private fun ClaimPathElement.toRegistrationClaimPathElement(): RegistrationClaimPathElement =
    when (this) {
        is ClaimPathElement.Claim -> RegistrationClaimPathElement.Claim(name)
        is ClaimPathElement.ArrayElement -> RegistrationClaimPathElement.ArrayElement(index)
        ClaimPathElement.AllArrayElements -> RegistrationClaimPathElement.AllArrayElements
    }
