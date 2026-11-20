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
package eu.europa.ec.eudi.wallet.disclosurepolicy

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils

/**
 * An embedded disclosure policy: the conditions that the attestation provider sets for the
 * relying parties that may receive a document (ETSI TS 119 472-3, clause 4.2.5).
 *
 * The encoding follows the changes to ETSI TS 119 472-3 clause 4.2.5 proposed in the comments of
 * 2026-08-11, which ETSI has not adopted yet.
 *
 * @property policyUri the URI that identifies the policy (`policy_uri`)
 * @property type the type of the policy, which applies to all attributes of the document (`policy`)
 * @property laymanUri the address of a page that explains the policy to the user (`layman_uri`,
 * ISS-MDATA-EBD-4.2.5.2-13)
 * @property claimPolicies the policies of single claims, which replace [type] for those claims
 * (`extensions.specific_attribute_policies`)
 */
internal data class EmbeddedDisclosurePolicy(
    val policyUri: String,
    val type: PolicyType,
    val laymanUri: String? = null,
    val claimPolicies: List<ClaimPolicy> = emptyList(),
) {

    /**
     * The policy of a single claim of the document.
     *
     * @property namespaceOrVct the namespace of the claim (ISO/IEC 18013-5), or the vct of the
     * document (SD-JWT VC)
     * @property attributeIdentifier the attribute identifier of the claim, as in the attestation
     * rulebook; for SD-JWT VC, the identifiers of nested claims are separated by `.`
     * @property type the type of the policy that applies to the claim
     */
    data class ClaimPolicy(val namespaceOrVct: String, val attributeIdentifier: String, val type: PolicyType)

    /**
     * The type of an embedded disclosure policy.
     */
    sealed interface PolicyType {

        /** No restriction applies (`"none"`). */
        data object None : PolicyType

        /**
         * Only the listed relying parties may receive the document (`authorized_rp_ids`).
         *
         * @property relyingParties the allowed relying parties
         */
        data class AuthorizedRelyingParties(val relyingParties: List<AuthorizedRelyingParty>) : PolicyType

        /**
         * Only relying parties whose registration certificate is signed, directly or indirectly, by a
         * certificate with one of the listed subjects may receive the document
         * (`authorized_cert_subject_DNs`).
         *
         * @property subjectDns the subject distinguished names, as RFC 4514 strings
         */
        data class AuthorizedCertificateSubjects(val subjectDns: List<String>) : PolicyType
    }

    companion object {
        /** The member of a credential configuration in the issuer metadata that holds the policy. */
        internal const val CREDENTIAL_CONFIGURATION_PARAMETER = "embedded_disclosure_policy"

        /**
         * Reads a policy from its JSON form.
         *
         * @param policy the JSON object of the policy
         * @return the policy, or `null` when the JSON is not a valid policy
         */
        internal fun fromJson(policy: JsonObject): EmbeddedDisclosurePolicy? =
            runCatching { policy.toPolicy() }.getOrNull()
    }
}

/**
 * A relying party that an embedded disclosure policy allows.
 */
internal sealed interface AuthorizedRelyingParty {

    /**
     * A service of a relying party registered in the EUDI Wallet ecosystem.
     *
     * @property wrpIdentifier the wallet-relying party identifier
     * @property serviceIdentifier the identifier of the service, as registered with the Registrar
     * (Technical Specification 5, `serviceIdentifier`); it is not compared, since no certificate
     * that the relying party presents carries it
     */
    data class WrpService(val wrpIdentifier: String, val serviceIdentifier: String) : AuthorizedRelyingParty

    /**
     * A relying party identified by the subject of its access certificate.
     *
     * @property subjectDn the subject distinguished name, as an RFC 4514 string
     */
    data class AccessCertificateSubject(val subjectDn: String) : AuthorizedRelyingParty
}

/**
 * The identifier of the relying party in this subject: the organization identifier, or for a
 * natural person the serial number. Only the identifier is compared with the access certificate.
 * Returns `null` when the subject has no identifier, or more than one value for it.
 */
internal fun AuthorizedRelyingParty.AccessCertificateSubject.relyingPartyIdentifier(): String? =
    policyDistinguishedName(subjectDn)?.let { runCatching { it.relyingPartyIdentifier() }.getOrNull() }

/**
 * Reads a distinguished name of a policy, with the attribute names used in policies (see
 * [PolicyNameStyle]). Comparing the result with another name ignores case and repeated spaces in
 * values, and accepts the attributes in the same or in reverse order.
 *
 * @return the name, or `null` when [dn] is not an RFC 4514 distinguished name
 */
internal fun policyDistinguishedName(dn: String): X500Name? = runCatching { X500Name(PolicyNameStyle, dn) }.getOrNull()

/**
 * Returns the identifier of a relying party in this name: the organization identifier, or for a
 * natural person the serial number. Returns `null` when the name has more than one value for the
 * identifier.
 */
internal fun X500Name.relyingPartyIdentifier(): String? {
    val organizationIdentifiers = values(BCStyle.ORGANIZATION_IDENTIFIER)
    if (organizationIdentifiers.isNotEmpty()) return organizationIdentifiers.singleOrNull()
    return values(BCStyle.SERIALNUMBER).singleOrNull()
}

private fun X500Name.values(type: ASN1ObjectIdentifier): List<String> =
    getRDNs(type)
        .flatMap { it.typesAndValues.asIterable() }
        .filter { it.type == type }
        .map { IETFUtils.valueToString(it.value) }

private const val POLICY_URI = "policy_uri"
private const val POLICY = "policy"
private const val LAYMAN_URI = "layman_uri"
private const val NONE = "none"
private const val AUTHORIZED_RP_IDS = "authorized_rp_ids"
private const val AUTHORIZED_CERT_SUBJECT_DNS = "authorized_cert_subject_DNs"
private const val EXTENSIONS = "extensions"
private const val SPECIFIC_ATTRIBUTE_POLICIES = "specific_attribute_policies"

private fun JsonObject.toPolicy(): EmbeddedDisclosurePolicy? {
    val policyUri = get(POLICY_URI)?.stringOrNull() ?: return null
    val laymanUri = get(LAYMAN_URI)?.let { it.stringOrNull() ?: return null }
    val type = get(POLICY)?.toPolicyType() ?: return null
    val claimPolicies = get(EXTENSIONS)?.let { (it as? JsonObject)?.toClaimPolicies() ?: return null }
    return EmbeddedDisclosurePolicy(policyUri, type, laymanUri, claimPolicies.orEmpty())
}

/**
 * Reads the `specific_attribute_policies` of the extensions; other extensions are ignored. Each key
 * is the namespace or vct and the attribute identifier of a claim separated by a comma, and each
 * value is a policy in the same form as `policy`. Two keys for the same claim are not valid.
 */
private fun JsonObject.toClaimPolicies(): List<EmbeddedDisclosurePolicy.ClaimPolicy>? {
    val policies = get(SPECIFIC_ATTRIBUTE_POLICIES) ?: return emptyList()
    return (policies as? JsonObject)
        ?.map { (key, value) ->
            val namespaceOrVct = key.substringBefore(',', missingDelimiterValue = "").trim()
            val attributeIdentifier = key.substringAfter(',', missingDelimiterValue = "").trim()
            if (namespaceOrVct.isEmpty() || attributeIdentifier.isEmpty()) return null
            EmbeddedDisclosurePolicy.ClaimPolicy(namespaceOrVct, attributeIdentifier, value.toPolicyType() ?: return null)
        }
        ?.takeIf { claimPolicies ->
            claimPolicies.distinctBy { it.namespaceOrVct to it.attributeIdentifier }.size == claimPolicies.size
        }
}

/**
 * Reads a policy: `"none"`, or an object with a single member named after the policy type. Empty
 * and duplicate entries are ignored; any other policy type is not valid.
 */
private fun JsonElement.toPolicyType(): EmbeddedDisclosurePolicy.PolicyType? {
    if (this is JsonPrimitive) return EmbeddedDisclosurePolicy.PolicyType.None.takeIf { stringOrNull() == NONE }
    val (name, value) = (this as? JsonObject)?.entries?.singleOrNull() ?: return null
    return when (name) {
        AUTHORIZED_RP_IDS -> value.nonEmptyStrings()
            ?.map { it.toAuthorizedRelyingParty() ?: return null }
            ?.distinct()
            ?.let { EmbeddedDisclosurePolicy.PolicyType.AuthorizedRelyingParties(it) }

        AUTHORIZED_CERT_SUBJECT_DNS -> value.nonEmptyStrings()
            ?.onEach { policyDistinguishedName(it) ?: return null }
            ?.let { EmbeddedDisclosurePolicy.PolicyType.AuthorizedCertificateSubjects(it) }

        else -> null
    }
}

/**
 * Reads an entry of `authorized_rp_ids`: an RFC 4514 subject distinguished name, or a wallet-relying
 * party identifier and a service identifier separated by a comma. Only a distinguished name contains
 * `=`.
 */
private fun String.toAuthorizedRelyingParty(): AuthorizedRelyingParty? =
    if ('=' in this) {
        policyDistinguishedName(this)?.let { AuthorizedRelyingParty.AccessCertificateSubject(subjectDn = this) }
    } else {
        val wrpIdentifier = substringBefore(',').trim()
        val serviceIdentifier = substringAfter(',', missingDelimiterValue = "").trim()
        if (wrpIdentifier.isEmpty() || serviceIdentifier.isEmpty()) null
        else AuthorizedRelyingParty.WrpService(wrpIdentifier, serviceIdentifier)
    }

private fun JsonElement.stringOrNull(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content

/**
 * The trimmed, distinct and non-empty strings of this array, or `null` when this is not an array
 * of strings.
 */
private fun JsonElement.nonEmptyStrings(): List<String>? =
    (this as? JsonArray)
        ?.map { it.stringOrNull()?.trim() ?: return null }
        ?.filter { it.isNotEmpty() }
        ?.distinct()

/**
 * The RFC 4514 attribute names used in embedded disclosure policies: `ORGID` is the
 * organizationIdentifier and `SN` is the serialNumber (ETSI TS 119 472-3, clause 4.2.5.2), and
 * `GN` is the givenName. The surname is written as `surname`.
 */
private object PolicyNameStyle : BCStyle() {
    override fun attrNameToOID(attrName: String): ASN1ObjectIdentifier =
        when (attrName.uppercase()) {
            "ORGID" -> BCStyle.ORGANIZATION_IDENTIFIER
            "SN" -> BCStyle.SERIALNUMBER
            "GN" -> BCStyle.GIVENNAME
            else -> super.attrNameToOID(attrName)
        }
}
