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

package eu.europa.ec.eudi.wallet.internal

import eu.europa.ec.eudi.wallet.dcapi.logging.Logger as DCAPILogger
import eu.europa.ec.eudi.wallet.logging.Logger as WalletLogger

/**
 * Adapts a wallet-core [WalletLogger] into a [DCAPILogger] so the DCAPI module can be
 * driven by the same logger configured via [eu.europa.ec.eudi.wallet.EudiWalletConfig].
 *
 * Both interfaces share an almost identical shape; each [DCAPILogger.Record] is
 * forwarded to the wallet-core logger by re-creating an equivalent [WalletLogger.Record].
 *
 * The log levels are mapped explicitly between the two `@IntDef`-annotated `Level`
 * domains. Even though the underlying numeric values currently match, the explicit
 * mapping makes the relationship between the two log-level taxonomies a compile-time
 * contract: if either side adds, removes, or renumbers a level in the future, this
 * mapping will need to be updated and the change will surface immediately.
 */
@JvmSynthetic
internal fun WalletLogger.asDCAPILogger(): DCAPILogger = DCAPILogger { record ->
    log(
        WalletLogger.Record(
            level = record.level.toWalletLogLevel(),
            instant = record.instant,
            message = record.message,
            thrown = record.thrown,
            sourceClassName = record.sourceClassName,
            sourceMethod = record.sourceMethod,
        )
    )
}

@WalletLogger.Level
private fun Int.toWalletLogLevel(): Int = when (this) {
    DCAPILogger.OFF -> WalletLogger.OFF
    DCAPILogger.LEVEL_ERROR -> WalletLogger.LEVEL_ERROR
    // wallet-core's Logger has no WARN level. Collapse to INFO, matching the existing
    // convention in LogPrinterImpl which maps multipaz's WARNING to LEVEL_INFO.
    DCAPILogger.LEVEL_WARN -> WalletLogger.LEVEL_INFO
    DCAPILogger.LEVEL_INFO -> WalletLogger.LEVEL_INFO
    DCAPILogger.LEVEL_DEBUG -> WalletLogger.LEVEL_DEBUG
    else -> WalletLogger.LEVEL_INFO
}
