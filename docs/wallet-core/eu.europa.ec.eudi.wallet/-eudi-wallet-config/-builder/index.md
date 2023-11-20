//[wallet-core](../../../../index.md)/[eu.europa.ec.eudi.wallet](../../index.md)/[EudiWalletConfig](../index.md)/[Builder](index.md)

# Builder

class [Builder](index.md)(context: [Context](https://developer.android.com/reference/kotlin/android/content/Context.html))

Builder

#### Parameters

androidJvm

| |
|---|
| context |

## Constructors

| | |
|---|---|
| [Builder](-builder.md) | [androidJvm]<br>constructor(context: [Context](https://developer.android.com/reference/kotlin/android/content/Context.html)) |

## Functions

| Name | Summary |
|---|---|
| [bleClearCacheEnabled](ble-clear-cache-enabled.md) | [androidJvm]<br>fun [bleClearCacheEnabled](ble-clear-cache-enabled.md)(bleClearCacheEnabled: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)): [EudiWalletConfig.Builder](index.md)<br>Ble clear cache enabled. If true, the BLE cache will be cleared after each transfer. |
| [bleTransferMode](ble-transfer-mode.md) | [androidJvm]<br>fun [bleTransferMode](ble-transfer-mode.md)(vararg bleTransferMode: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html)): [EudiWalletConfig.Builder](index.md)<br>Ble transfer mode. This is the BLE transfer mode. It can be [BLE_SERVER_PERIPHERAL_MODE](../-companion/-b-l-e_-s-e-r-v-e-r_-p-e-r-i-p-h-e-r-a-l_-m-o-d-e.md), [BLE_CLIENT_CENTRAL_MODE](../-companion/-b-l-e_-c-l-i-e-n-t_-c-e-n-t-r-a-l_-m-o-d-e.md) or both. |
| [build](build.md) | [androidJvm]<br>fun [build](build.md)(): [EudiWalletConfig](../index.md)<br>Build the [EudiWalletConfig](../index.md) object |
| [documentsStorageDir](documents-storage-dir.md) | [androidJvm]<br>fun [documentsStorageDir](documents-storage-dir.md)(documentStorageDir: [File](https://developer.android.com/reference/kotlin/java/io/File.html)): [EudiWalletConfig.Builder](index.md)<br>Documents storage dir. This is the directory where the documents will be stored. If not set, the default directory is the noBackupFilesDir. |
| [encryptDocumentsInStorage](encrypt-documents-in-storage.md) | [androidJvm]<br>fun [encryptDocumentsInStorage](encrypt-documents-in-storage.md)(encryptDocumentsInStorage: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)): [EudiWalletConfig.Builder](index.md)<br>Encrypt documents in storage. If true, the documents will be encrypted in the storage. |
| [openId4VpVerifierApiUri](open-id4-vp-verifier-api-uri.md) | [androidJvm]<br>fun [openId4VpVerifierApiUri](open-id4-vp-verifier-api-uri.md)(openId4VpVerifierUri: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [EudiWalletConfig.Builder](index.md)<br>OpenId4Vp verifier uri This is the uri of the OpenId4Vp verifier |
| [trustedReaderCertificates](trusted-reader-certificates.md) | [androidJvm]<br>fun [trustedReaderCertificates](trusted-reader-certificates.md)(@[RawRes](https://developer.android.com/reference/kotlin/androidx/annotation/RawRes.html)vararg rawIds: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html)): [EudiWalletConfig.Builder](index.md)<br>Trusted reader certificates This is the list of trusted reader certificates as raw resource ids.<br>[androidJvm]<br>fun [trustedReaderCertificates](trusted-reader-certificates.md)(trustedReaderCertificates: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;): [EudiWalletConfig.Builder](index.md)<br>Trusted reader certificates. This is the list of trusted reader certificates. |
| [useHardwareToStoreKeys](use-hardware-to-store-keys.md) | [androidJvm]<br>fun [useHardwareToStoreKeys](use-hardware-to-store-keys.md)(useHardwareToStoreKeys: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)): [EudiWalletConfig.Builder](index.md)<br>Use hardware to store keys. If true and supported by device, documents' keys will be stored in the hardware. |
| [userAuthenticationRequired](user-authentication-required.md) | [androidJvm]<br>fun [userAuthenticationRequired](user-authentication-required.md)(userAuthenticationRequired: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)): [EudiWalletConfig.Builder](index.md)<br>User authentication required. If true, the user will be asked to authenticate before accessing the documents' attestations. |
| [userAuthenticationTimeOut](user-authentication-time-out.md) | [androidJvm]<br>fun [userAuthenticationTimeOut](user-authentication-time-out.md)(userAuthenticationTimeout: [Long](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-long/index.html)): [EudiWalletConfig.Builder](index.md)<br>User authentication time out. This is the time out for the user authentication. |