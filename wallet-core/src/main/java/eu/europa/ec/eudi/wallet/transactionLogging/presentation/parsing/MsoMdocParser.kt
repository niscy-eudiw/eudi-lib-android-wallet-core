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

package eu.europa.ec.eudi.wallet.transactionLogging.presentation.parsing

import com.android.identity.mdoc.response.DeviceResponseParser
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.metadata.DocumentMetaData
import eu.europa.ec.eudi.wallet.transactionLogging.presentation.PresentedClaim
import eu.europa.ec.eudi.wallet.transactionLogging.presentation.PresentedDocument
import eu.europa.ec.eudi.wallet.util.CBOR

/**
 * Parses the MSO mdoc response and returns a list of presented documents.
 *
 * @param rawResponse The raw response byte array from the device.
 * @param sessionTranscript The session transcript byte array, or null if not available.
 * @param metadata A list of metadata strings, or null if not available.
 * @return A list of presented documents.
 */
fun parseMsoMdoc(
    rawResponse: ByteArray,
    sessionTranscript: ByteArray?,
    metadata: List<String?>?
): List<PresentedDocument> {
    // Parse the raw response using the DeviceResponseParser
    val parsed = DeviceResponseParser(
        rawResponse,
        sessionTranscript ?: byteArrayOf(0)
    ).parse()

    // Convert metadata strings to DocumentMetaData objects
    val documentMetadata = metadata?.map { it?.let { DocumentMetaData.fromJson(it) } }

    // Map parsed documents to PresentedDocument objects
    return parsed.documents.mapIndexed { index, doc ->
        // Extract claims from the document
        val claims = doc.issuerNamespaces.flatMap { nameSpace ->
            doc.getIssuerEntryNames(nameSpace).map { elementIdentifier ->
                val data = doc.getIssuerEntryData(nameSpace, elementIdentifier)
                PresentedClaim(
                    path = listOf(nameSpace, elementIdentifier),
                    value = CBOR.cborParse(data),
                    rawValue = data,
                    metadata = documentMetadata?.getOrNull(index)?.claims?.find {
                        it.name is DocumentMetaData.Claim.Name.MsoMdoc && it.name.name == elementIdentifier
                    }
                )
            }
        }
        // Create a PresentedDocument object
        PresentedDocument(
            format = MsoMdocFormat(docType = doc.docType),
            metadata = documentMetadata?.getOrNull(index),
            claims = claims
        )
    }
}