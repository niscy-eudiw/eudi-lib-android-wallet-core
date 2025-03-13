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
import eu.europa.ec.eudi.openid4vci.ClaimPath
import eu.europa.ec.eudi.openid4vci.ClaimPathElement
import eu.europa.ec.eudi.openid4vci.Display
import eu.europa.ec.eudi.wallet.document.metadata.DocumentMetaData
import eu.europa.ec.eudi.wallet.issue.openid4vci.Offer.OfferedDocument

fun OfferedDocument.extractDocumentMetaData(): DocumentMetaData {

    val documentDisplay = this.configuration.display.map { it.toDocumentDisplay() }

    val claims = configuration.claims?.map {
        it.toDocumentMetaDataClaim()
    }

    return DocumentMetaData(
        credentialIssuerIdentifier = offer.credentialOffer.credentialIssuerIdentifier.value.value.toString(),
        documentConfigurationIdentifier = configurationIdentifier.value,
        display = documentDisplay,
        claims = claims,
        issuerDisplay = this.offer.issuerMetadata.display.map {
            DocumentMetaData.IssuerDisplay(
                name = it.name,
                locale = it.locale,
                logo = it.logo?.toDocumentLogo()
            )
        }
    )
}

private fun Display.toDocumentDisplay(): DocumentMetaData.Display = DocumentMetaData.Display(
    name = name,
    locale = locale,
    logo = logo?.toDocumentLogo(),
    description = description,
    backgroundColor = backgroundColor,
    textColor = textColor,
    backgroundImageUri = backgroundImage
)

private fun Display.Logo.toDocumentLogo():
        DocumentMetaData.Logo =
    DocumentMetaData.Logo(uri, alternativeText)


private fun Claim?.toDocumentMetaDataClaim(): DocumentMetaData.Claim =
    DocumentMetaData.Claim(
        path = this?.path?.toMetaDataClaimName() ?: emptyList(),
        mandatory = this?.mandatory,
        display = this?.display?.map { display ->
            DocumentMetaData.Claim.Display(
                name = display.name,
                locale = display.locale
            )
        } ?: emptyList()
    )

private fun ClaimPath.toMetaDataClaimName(): List<String> {
    return value.filterIsInstance<ClaimPathElement.Claim>().map { it.name }.toList()
}