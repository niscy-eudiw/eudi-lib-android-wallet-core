/*
 * Copyright (c) 2023 European Commission
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

package eu.europa.ec.eudi.wallet.util

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.model.AbstractFloat
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.DoublePrecisionFloat
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.Tag
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream
import java.time.LocalDate
import java.time.ZonedDateTime

/*
 * Utility object for encoding and decoding CBOR (Concise Binary Object Representation) data.
 */
object CBOR {
    /**
     * Decodes a given CBOR byte array into a [DataItem].
     *
     * @param encodedBytes The byte array to decode.
     * @return The decoded [DataItem].
     * @throws IllegalArgumentException If decoding fails or the number of decoded items is not 1.
     */
    @JvmStatic
    fun cborDecode(encodedBytes: ByteArray): DataItem {
        return ByteArrayInputStream(encodedBytes).use { stream ->
            try {
                val dataItems: List<DataItem> = CborDecoder(stream).decode()
                require(dataItems.size == 1) {
                    "Unexpected number of items, expected 1 got ${dataItems.size}"
                }
                dataItems[0]
            } catch (e: CborException) {
                throw IllegalArgumentException("Error decoding CBOR", e)
            }
        }
    }

    /**
     * Parses a given CBOR byte array into a Kotlin object.
     *
     * @param data The CBOR byte array to parse.
     * @return The parsed object.
     */
    fun cborParse(data: ByteArray): Any? {
        val dataItem = cborDecode(data)
        return cborParse(dataItem)
    }

    /**
     * Parses a given [DataItem] into a Kotlin object.
     *
     * @param dataItem The [DataItem] to parse.
     * @return The parsed object.
     */
    private fun cborParse(dataItem: DataItem): Any? {
        return when (dataItem.majorType) {
            MajorType.INVALID -> "invalid"
            MajorType.UNSIGNED_INTEGER -> (dataItem as UnsignedInteger).value.toLong()
            MajorType.NEGATIVE_INTEGER -> (dataItem as NegativeInteger).value.toLong()
            MajorType.BYTE_STRING -> (dataItem as ByteString).bytes
            MajorType.UNICODE_STRING -> {
                val value = (dataItem as UnicodeString).string
                when {
                    dataItem.tag == Tag(0) -> ZonedDateTime.parse(value)
                    dataItem.tag == Tag(1004) -> LocalDate.parse(value)
                    else -> value
                }
            }

            MajorType.ARRAY -> (dataItem as Array).dataItems.map { cborParse(it) }
            MajorType.MAP -> {
                val map = (dataItem as Map)
                map.keys.associate { cborParse(it) to cborParse(map[it]) }
            }

            MajorType.TAG -> null
            MajorType.SPECIAL -> when (dataItem) {
                is SimpleValue -> when (dataItem.simpleValueType) {
                    SimpleValueType.FALSE -> false
                    SimpleValueType.TRUE -> true
                    SimpleValueType.NULL -> null
                    SimpleValueType.UNDEFINED -> "undefined"
                    SimpleValueType.RESERVED -> "reserved"
                    SimpleValueType.UNALLOCATED -> "unallocated"
                }

                is DoublePrecisionFloat -> dataItem.value
                is AbstractFloat -> dataItem.value.toDouble()
                else -> null
            }
        }
    }
}