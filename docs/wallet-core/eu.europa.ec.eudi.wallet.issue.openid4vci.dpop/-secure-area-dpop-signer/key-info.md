//[wallet-core](../../../index.md)/[eu.europa.ec.eudi.wallet.issue.openid4vci.dpop](../index.md)/[SecureAreaDpopSigner](index.md)/[keyInfo](key-info.md)

# keyInfo

[androidJvm]\
val [keyInfo](key-info.md): KeyInfo

Information about the DPoP key created in the secure area.

This property is initialized during object construction by creating a new key using the algorithms and key settings from the configuration. The configuration's [DPopConfig.Custom.createKeySettingsBuilder](../-d-pop-config/-custom/create-key-settings-builder.md) function receives the list of supported algorithms and selects an appropriate one for key creation. The key is created synchronously using runBlocking to ensure it's available immediately.

The KeyInfo contains:

- 
   **alias**: The unique identifier for the key in the secure area
- 
   **algorithm**: The cryptographic algorithm selected by the configuration's builder
- 
   **publicKey**: The public key material in EC format
