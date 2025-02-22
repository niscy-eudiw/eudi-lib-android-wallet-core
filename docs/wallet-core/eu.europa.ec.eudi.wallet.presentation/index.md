//[wallet-core](../../index.md)/[eu.europa.ec.eudi.wallet.presentation](index.md)

# Package-level declarations

## Types

| Name | Summary |
|---|---|
| [PresentationManager](-presentation-manager/index.md) | [androidJvm]<br>interface [PresentationManager](-presentation-manager/index.md) : TransferEvent.Listenable, ReaderTrustStoreAware<br>The PresentationManager is responsible for managing the presentation of the wallet's documents to the verifier. The wallet can present the documents in two ways: |
| [PresentationManagerImpl](-presentation-manager-impl/index.md) | [androidJvm]<br>class [PresentationManagerImpl](-presentation-manager-impl/index.md)@[JvmOverloads](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)constructor(transferManager: TransferManager, openId4vpManager: [OpenId4VpManager](../eu.europa.ec.eudi.wallet.transfer.openId4vp/-open-id4-vp-manager/index.md)? = null, val nfcEngagementServiceClass: [Class](https://developer.android.com/reference/kotlin/java/lang/Class.html)&lt;out NfcEngagementService&gt;? = null) : [PresentationManager](-presentation-manager/index.md)<br>Implementation of the [PresentationManager](-presentation-manager/index.md) interface based on the TransferManager and [OpenId4VpManager](../eu.europa.ec.eudi.wallet.transfer.openId4vp/-open-id4-vp-manager/index.md) implementations. |
| [SessionTerminationFlag](-session-termination-flag/index.md) | [androidJvm]<br>annotation class [SessionTerminationFlag](-session-termination-flag/index.md)<br>Annotation that defines the possible flags for session termination. |
