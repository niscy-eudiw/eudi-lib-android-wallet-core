//[wallet-core](../../../index.md)/[eu.europa.ec.eudi.wallet](../index.md)/[EudiWalletConfig](index.md)/[configureIssuerTrust](configure-issuer-trust.md)

# configureIssuerTrust

[androidJvm]\
fun [configureIssuerTrust](configure-issuer-trust.md)(block: [IssuerTrustConfigBuilder](../../eu.europa.ec.eudi.wallet.trust/-issuer-trust-config-builder/index.md).() -&gt; [Unit](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin-stdlib/kotlin/-unit/index.html)): &lt;Error class: unknown class&gt;

Configure issuer trust verification for credentials issued via OpenID4VCI. Trust verification occurs after issuance, before storage. When not configured, trust verification is skipped entirely.

#### Return

the [EudiWalletConfig](index.md) instance

#### Parameters

androidJvm

| | |
|---|---|
| block | configuration block applied to the [IssuerTrustConfigBuilder](../../eu.europa.ec.eudi.wallet.trust/-issuer-trust-config-builder/index.md) |

#### See also

| |
|---|
| [IssuerTrustConfigBuilder](../../eu.europa.ec.eudi.wallet.trust/-issuer-trust-config-builder/index.md) |
