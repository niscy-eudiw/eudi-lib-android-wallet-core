/*
 * Copyright (c) 2024 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci.transformations

import eu.europa.ec.eudi.openid4vci.Claim
import eu.europa.ec.eudi.openid4vci.CredentialConfiguration
import eu.europa.ec.eudi.openid4vci.Display
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.wallet.document.metadata.DocumentMetadata

internal fun CredentialConfiguration.extractDocumentMetadata(): DocumentMetadata {
    val documentDisplay = display.map { it.toDocumentDisplay() }

    val claims = when (this) {
        is MsoMdocCredential -> claims.fromMsoDocToDocumentClaim()
        is SdJwtVcCredential -> claims.fromSdJwtVToDocumentClaim()
        else -> null
    }

    return DocumentMetadata(
        display = documentDisplay,
        claims = claims
    )
}

private fun Display.toDocumentDisplay(): DocumentMetadata.Display = DocumentMetadata.Display(
    name = name,
    locale = locale,
    logo = logo?.toDocumentLogo(),
    description = description,
    backgroundColor = backgroundColor,
    textColor = textColor
)

private fun Display.Logo.toDocumentLogo():
        DocumentMetadata.Display.Logo =
    DocumentMetadata.Display.Logo(uri, alternativeText)

private fun Map<String, Map<String, Claim>>.fromMsoDocToDocumentClaim(): List<DocumentMetadata.Claim> {

    return this.flatMap { (namespace, claimsMap) ->
        claimsMap.mapNotNull { (name, claim) ->
            val claimName = DocumentMetadata.Claim.Name.MsoMdoc(
                name = name,
                nameSpace = namespace
            )
            claim.fromMsoDocToDocumentClaim(claimName)
        }
    }
}

private fun Map<String, Claim?>?.fromSdJwtVToDocumentClaim(): List<DocumentMetadata.Claim>? {
    return this?.mapNotNull { (name, claim) ->
        val claimName = DocumentMetadata.Claim.Name.SdJwtVc(name = name)
        claim.fromMsoDocToDocumentClaim(claimName)
    }
}

private fun Claim?.fromMsoDocToDocumentClaim(name: DocumentMetadata.Claim.Name): DocumentMetadata.Claim =
    DocumentMetadata.Claim(
        name = name,
        mandatory = this?.mandatory,
        valueType = this?.valueType,
        display = this?.display?.map { display ->
            DocumentMetadata.Claim.Display(
                name = display.name,
                locale = display.locale
            )
        } ?: emptyList()
    )