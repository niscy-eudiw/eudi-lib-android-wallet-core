//[wallet-core](../../../index.md)/[eu.europa.ec.eudi.wallet.transactionLogging.presentation](../index.md)/[TransactionLogBuilder](index.md)/[withResponse](with-response.md)

# withResponse

[androidJvm]\
fun [withResponse](with-response.md)(log: [TransactionLog](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/index.md), response: Response, error: [Throwable](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin-stdlib/kotlin/-throwable/index.html)? = null): [TransactionLog](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/index.md)

Updates the provided [TransactionLog](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/index.md) with information from a Response and an optional [Throwable](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin-stdlib/kotlin/-throwable/index.html).

If the log's type is not [TransactionLog.Type.Presentation](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/-type/-presentation/index.md), it returns the log unchanged. It handles different types of responses:

- 
   DeviceResponse: Stores raw response bytes, document metadata, session transcript, and sets format to CBOR.
- 
   [OpenId4VpResponse.DeviceResponse](../../eu.europa.ec.eudi.wallet.transfer.openId4vp/-open-id4-vp-response/-device-response/index.md): Similar to DeviceResponse.
- 
   [OpenId4VpResponse.GenericResponse](../../eu.europa.ec.eudi.wallet.transfer.openId4vp/-open-id4-vp-response/-generic-response/index.md): Stores a JSON representation of verifiable presentations and presentation submission, document metadata, and sets format to JSON. Requires the VP content to be VpContent.PresentationExchange.
- 
   Other response types: Throws an [IllegalArgumentException](https://developer.android.com/reference/kotlin/java/lang/IllegalArgumentException.html).

The log status is set to [TransactionLog.Status.Completed](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/-status/-completed/index.md) if `error` is null, otherwise to [TransactionLog.Status.Error](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/-status/-error/index.md). The timestamp of the log is updated to the current time.

#### Return

An updated [TransactionLog](../../eu.europa.ec.eudi.wallet.transactionLogging/-transaction-log/index.md) instance.

#### Parameters

androidJvm

| | |
|---|---|
| log | The current transaction log to update. |
| response | The response object. |
| error | An optional error that occurred during response processing. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://developer.android.com/reference/kotlin/java/lang/IllegalArgumentException.html) | if an unsupported response type is provided or if [OpenId4VpResponse.GenericResponse](../../eu.europa.ec.eudi.wallet.transfer.openId4vp/-open-id4-vp-response/-generic-response/index.md) does not contain VpContent.PresentationExchange. |
