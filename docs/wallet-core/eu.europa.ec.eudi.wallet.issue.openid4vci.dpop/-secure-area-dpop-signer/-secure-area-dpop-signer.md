//[wallet-core](../../../index.md)/[eu.europa.ec.eudi.wallet.issue.openid4vci.dpop](../index.md)/[SecureAreaDpopSigner](index.md)/[SecureAreaDpopSigner](-secure-area-dpop-signer.md)

# SecureAreaDpopSigner

[androidJvm]\
constructor(config: [DPopConfig.Custom](../-d-pop-config/-custom/index.md), algorithms: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;Algorithm&gt;, logger: [Logger](../../eu.europa.ec.eudi.wallet.logging/-logger/index.md)? = null)

Creates a new DPoP signer with a key in the specified secure area.     A DPoP key is created immediately during construction using the provided     algorithms and configuration settings.     **Note:** This constructor is typically called by DPopSigner.makeIfSupported     and should not be invoked directly by application code.

#### Parameters

androidJvm

| | |
|---|---|
| algorithms | The list of cryptographic algorithms supported by both the authorization     server and the secure area (e.g., ES256, ES384, ES512). This list is passed to the     configuration's [DPopConfig.Custom.createKeySettingsBuilder](../-d-pop-config/-custom/create-key-settings-builder.md) to create the key with     an appropriate algorithm. The list is determined during DPopSigner.makeIfSupported     based on compatibility between the server and secure area. |
| logger | Optional logger for debugging and tracking DPoP key creation and signing operations. |
