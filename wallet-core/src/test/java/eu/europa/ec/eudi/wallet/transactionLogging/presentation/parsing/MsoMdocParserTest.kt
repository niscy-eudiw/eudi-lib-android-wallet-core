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

import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import org.junit.Test
import kotlin.test.assertEquals

class MsoMdocParserTest {

    @Test
    fun `test parceCbor`() {
        val data = getResourceAsByteArrayFromBase64Url("mso_mdoc_response.txt")
        val sessionTranscript = byteArrayOf(0)
        val metadata = listOf<String>()
        val result = parseMsoMdoc(data, sessionTranscript, metadata)
        assertEquals(1, result.size)
        val presentedDocument = result.first()

        assertEquals(MsoMdocFormat(docType = "org.iso.18013.5.1.mDL"), presentedDocument.format)
        assertEquals(13, presentedDocument.claims.size)

    }
}