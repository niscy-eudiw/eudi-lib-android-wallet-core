//[wallet-core](../../../index.md)/[eu.europa.ec.eudi.wallet.issue.openid4vci](../index.md)/[DeferredIssuanceStoredContextTO](index.md)/[DeferredIssuanceStoredContextTO](-deferred-issuance-stored-context-t-o.md)

# DeferredIssuanceStoredContextTO

[androidJvm]\
constructor(
credentialIssuerId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
clientId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
clientAttestationJwt: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? =
null,
clientAttestationPopDuration: [Long](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-long/index.html)? =
null,
clientAttestationPopAlgorithm: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? =
null,
clientAttestationPopType: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? =
null,
clientAttestationPopKeyId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? =
null,
deferredEndpoint: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
authServerId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
tokenEndpoint: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
dPoPSignerKid: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? =
null, responseEncryptionSpec: JsonObject? = null,
transactionId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html),
accessToken: [AccessTokenTO](../-access-token-t-o/index.md),
refreshToken: [RefreshTokenTO](../-refresh-token-t-o/index.md)? = null,
authorizationTimestamp: [Long](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-long/index.html))