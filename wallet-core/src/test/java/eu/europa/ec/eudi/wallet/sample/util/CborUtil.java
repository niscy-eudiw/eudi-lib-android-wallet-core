/*
 * Copyright (c) 2024-2025 European Commission
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

package eu.europa.ec.eudi.wallet.sample.util;

import androidx.annotation.NonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.AbstractFloat;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.DoublePrecisionFloat;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 * Utility functions for cbor encoding/ decoding and other
 */
public class CborUtil {
    private static final long CBOR_SEMANTIC_TAG_ENCODED_CBOR = 24;

    // Not called.
    private CborUtil() {
    }


    protected static @NonNull
    byte[] cborEncode(@NonNull DataItem dataItem) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new CborEncoder(baos).encode(dataItem);
        } catch (CborException e) {
            // This should never happen and we don't want cborEncode() to throw since that
            // would complicate all callers. Log it instead.
            throw new IllegalStateException("Unexpected failure encoding data", e);
        }
        return baos.toByteArray();
    }


    protected static @NonNull
    DataItem cborDecode(@NonNull byte[] encodedBytes) {
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedBytes);
        List<DataItem> dataItems = null;
        try {
            dataItems = new CborDecoder(bais).decode();
        } catch (CborException e) {
            throw new IllegalArgumentException("Error decoding CBOR", e);
        }
        if (dataItems.size() != 1) {
            throw new IllegalArgumentException("Unexpected number of items, expected 1 got "
                    + dataItems.size());
        }
        return dataItems.get(0);
    }


    protected static boolean cborDecodeBoolean(@NonNull byte[] data) {
        SimpleValue simple = (SimpleValue) cborDecode(data);
        return simple.getSimpleValueType() == SimpleValueType.TRUE;
    }

    /**
     * Accepts a {@code DataItem}, attempts to cast it to a {@code Number}, then returns the value
     * Throws {@code IllegalArgumentException} if the {@code DataItem} is not a {@code Number}. This
     * method also checks bounds, and if the given data item is too large to fit in a long, it
     * throws {@code ArithmeticException}.
     */

    protected static long checkedLongValue(DataItem item) {
        final BigInteger bigNum = castTo(Number.class, item).getValue();
        final long result = bigNum.longValue();
        if (!bigNum.equals(BigInteger.valueOf(result))) {
            throw new ArithmeticException("Expected long value, got '" + bigNum + "'");
        }
        return result;
    }


    protected static @NonNull
    String cborDecodeString(@NonNull byte[] data) {
        return checkedStringValue(cborDecode(data));
    }

    /**
     * Accepts a {@code DataItem}, attempts to cast it to a {@code UnicodeString}, then returns the
     * value. Throws {@code IllegalArgumentException} if the {@code DataItem} is not a
     * {@code UnicodeString}.
     */

    protected static String checkedStringValue(DataItem item) {
        return castTo(UnicodeString.class, item).getString();
    }


    protected static long cborDecodeLong(@NonNull byte[] data) {
        return checkedLongValue(cborDecode(data));
    }


    public static @NonNull
    byte[] cborDecodeByteString(@NonNull byte[] data) {
        DataItem dataItem = cborDecode(data);
        return castTo(ByteString.class, dataItem).getBytes();
    }

    /**
     * Similar to a typecast of {@code value} to the given type {@code clazz}, except:
     * <ul>
     *   <li>Throws {@code IllegalArgumentException} instead of {@code ClassCastException} if
     *       {@code !clazz.isAssignableFrom(value.getClass())}.</li>
     *   <li>Also throws {@code IllegalArgumentException} if {@code value == null}.</li>
     * </ul>
     */

    protected static @NonNull <T extends V, V> T castTo(Class<T> clazz, V value) {
        if (value == null || !clazz.isAssignableFrom(value.getClass())) {
            String valueStr = (value == null) ? "null" : value.getClass().toString();
            throw new IllegalArgumentException("Expected type " + clazz + ", got type " + valueStr);
        } else {
            return (T) value;
        }
    }

    /**
     * For a #6.24(bstr), extracts the bytes and decodes it and returns
     * the decoded CBOR as a DataItem.
     */

    protected static @NonNull
    DataItem cborExtractTaggedAndEncodedCbor(@NonNull DataItem item) {
        ByteString itemByteString = castTo(ByteString.class, item);
        if (!item.hasTag() || item.getTag().getValue() != CBOR_SEMANTIC_TAG_ENCODED_CBOR) {
            throw new IllegalArgumentException("ByteString is not tagged with tag 24");
        }
        byte[] encodedCbor = itemByteString.getBytes();
        return cborDecode(encodedCbor);
    }


    protected static @NonNull
    String cborMapExtractString(@NonNull DataItem map,
                                @NonNull String key) {
        DataItem item = castTo(Map.class, map).get(new UnicodeString(key));
        return checkedStringValue(item);
    }


    protected static @NonNull
    List<DataItem> cborMapExtractArray(@NonNull DataItem map,
                                       @NonNull String key) {
        DataItem item = castTo(Map.class, map).get(new UnicodeString(key));
        return castTo(Array.class, item).getDataItems();
    }


    protected static @NonNull
    DataItem cborMapExtractMap(@NonNull DataItem map,
                               @NonNull String key) {
        DataItem item = castTo(Map.class, map).get(new UnicodeString(key));
        return castTo(Map.class, item);
    }


    protected static @NonNull
    Collection<String> cborMapExtractMapStringKeys(@NonNull DataItem map) {
        List<String> ret = new ArrayList<>();
        for (DataItem item : castTo(Map.class, map).getKeys()) {
            ret.add(checkedStringValue(item));
        }
        return ret;
    }


    protected static @NonNull
    DataItem cborMapExtract(@NonNull DataItem map, @NonNull String key) {
        DataItem item = castTo(Map.class, map).get(new UnicodeString(key));
        if (item == null) {
            throw new IllegalArgumentException("Expected item");
        }
        return item;
    }


    protected static @NonNull
    String cborPrettyPrint(@NonNull DataItem dataItem) {
        StringBuilder sb = new StringBuilder();
        cborPrettyPrintDataItem(sb, 0, dataItem);
        return sb.toString();
    }


    public static @NonNull
    String cborPrettyPrint(@NonNull byte[] encodedBytes) {
        StringBuilder sb = new StringBuilder();

        ByteArrayInputStream bais = new ByteArrayInputStream(encodedBytes);
        List<DataItem> dataItems = null;
        try {
            dataItems = new CborDecoder(bais).decode();
        } catch (CborException e) {
            throw new IllegalStateException(e);
        }
        int count = 0;
        for (DataItem dataItem : dataItems) {
            if (count > 0) {
                sb.append(",\n");
            }
            cborPrettyPrintDataItem(sb, 0, dataItem);
            count++;
        }

        return sb.toString();
    }

    // Returns true iff all elements in |items| are not compound (e.g. an array or a map).

    protected static boolean cborAreAllDataItemsNonCompound(@NonNull List<DataItem> items) {
        for (DataItem item : items) {
            switch (item.getMajorType()) {
                case ARRAY, MAP:
                    return false;
                default:
                    // Do nothing
                    break;
            }
        }
        return true;
    }


    protected static void cborPrettyPrintDataItem(@NonNull StringBuilder sb, int indent,
                                                  @NonNull DataItem dataItem) {
        StringBuilder indentBuilder = new StringBuilder();
        for (int n = 0; n < indent; n++) {
            indentBuilder.append(' ');
        }
        String indentString = indentBuilder.toString();

        if (dataItem.hasTag()) {
            sb.append(String.format(Locale.US, "tag %d ", dataItem.getTag().getValue()));
        }

        switch (dataItem.getMajorType()) {
            case INVALID:
                sb.append("<invalid>");
                break;
            case UNSIGNED_INTEGER: {
                // Major type 0: an unsigned integer.
                BigInteger value = ((UnsignedInteger) dataItem).getValue();
                sb.append(value);
            }
            break;
            case NEGATIVE_INTEGER: {
                // Major type 1: a negative integer.
                BigInteger value = ((NegativeInteger) dataItem).getValue();
                sb.append(value);
            }
            break;
            case BYTE_STRING: {
                // Major type 2: a byte string.
                byte[] value = ((ByteString) dataItem).getBytes();
                sb.append("[");
                int count = 0;
                for (byte b : value) {
                    if (count > 0) {
                        sb.append(", ");
                    }
                    sb.append(String.format("0x%02x", b));
                    count++;
                }
                sb.append("]");
            }
            break;
            case UNICODE_STRING: {
                // Major type 3: string of Unicode characters that is encoded as UTF-8 [RFC3629].
                String value = checkedStringValue(dataItem);
                sb.append("'" + value + "'");
            }
            break;
            case ARRAY: {
                // Major type 4: an array of data items.
                List<DataItem> items = ((Array) dataItem).getDataItems();
                if (items.size() == 0) {
                    sb.append("[]");
                } else if (cborAreAllDataItemsNonCompound(items)) {
                    // The case where everything fits on one line.
                    sb.append("[");
                    int count = 0;
                    for (DataItem item : items) {
                        cborPrettyPrintDataItem(sb, indent, item);
                        if (++count < items.size()) {
                            sb.append(", ");
                        }
                    }
                    sb.append("]");
                } else {
                    sb.append("[\n" + indentString);
                    int count = 0;
                    for (DataItem item : items) {
                        sb.append("  ");
                        cborPrettyPrintDataItem(sb, indent + 2, item);
                        if (++count < items.size()) {
                            sb.append(",");
                        }
                        sb.append("\n" + indentString);
                    }
                    sb.append("]");
                }
            }
            break;
            case MAP: {
                // Major type 5: a map of pairs of data items.
                Collection<DataItem> keys = ((Map) dataItem).getKeys();
                if (keys.size() == 0) {
                    sb.append("{}");
                } else {
                    sb.append("{\n" + indentString);
                    int count = 0;
                    for (DataItem key : keys) {
                        sb.append("  ");
                        DataItem value = ((Map) dataItem).get(key);
                        cborPrettyPrintDataItem(sb, indent + 2, key);
                        sb.append(" : ");
                        cborPrettyPrintDataItem(sb, indent + 2, value);
                        if (++count < keys.size()) {
                            sb.append(",");
                        }
                        sb.append("\n" + indentString);
                    }
                    sb.append("}");
                }
            }
            break;
            case TAG:
                // Major type 6: optional semantic tagging of other major types
                //
                // We never encounter this one since it's automatically handled via the
                // DataItem that is tagged.
                throw new IllegalStateException("Semantic tag data item not expected");

            case SPECIAL:
                // Major type 7: floating point numbers and simple data types that need no
                // content, as well as the "break" stop code.
                if (dataItem instanceof SimpleValue) {
                    switch (((SimpleValue) dataItem).getSimpleValueType()) {
                        case FALSE:
                            sb.append("false");
                            break;
                        case TRUE:
                            sb.append("true");
                            break;
                        case NULL:
                            sb.append("null");
                            break;
                        case UNDEFINED:
                            sb.append("undefined");
                            break;
                        case RESERVED:
                            sb.append("reserved");
                            break;
                        case UNALLOCATED:
                            sb.append("unallocated");
                            break;
                    }
                } else if (dataItem instanceof DoublePrecisionFloat) {
                    DecimalFormat df = new DecimalFormat("0",
                            DecimalFormatSymbols.getInstance(Locale.ENGLISH));
                    df.setMaximumFractionDigits(340);
                    sb.append(df.format(((DoublePrecisionFloat) dataItem).getValue()));
                } else if (dataItem instanceof AbstractFloat) {
                    DecimalFormat df = new DecimalFormat("0",
                            DecimalFormatSymbols.getInstance(Locale.ENGLISH));
                    df.setMaximumFractionDigits(340);
                    sb.append(df.format(((AbstractFloat) dataItem).getValue()));
                } else {
                    sb.append("break");
                }
                break;
        }
    }

}
