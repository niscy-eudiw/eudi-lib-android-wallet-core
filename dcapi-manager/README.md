# EUDI DCAPI Manager library for Android

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Overview

This module provides the EUDI Wallet's implementation of the
[Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/) (DCAPI)
on Android. It allows a wallet to register its mdoc credentials with the system
Credential Manager so they become discoverable by verifier apps and websites that
issue credential requests through the platform credential picker.

The current implementation follows the protocol `org-iso-mdoc`, as defined in
[ISO/IEC TS 18013-7:2025](https://www.iso.org/standard/91154.html) **Annex C**.

The library can be used in two ways:

- As a transitive dependency of [`eudi-lib-android-wallet-core`](../README.md). In
  that case, DCAPI is enabled and configured via `EudiWalletConfig.configureDCAPI`.
  See [DIGITAL_CREDENTIAL_API.md](../DIGITAL_CREDENTIAL_API.md) for details.
- **As a standalone module**, for consumers that want DCAPI functionality without
  pulling the rest of `eudi-lib-android-wallet-core` (e.g., apps that build their
  own integration on top of `eudi-lib-android-wallet-document-manager` and
  `eudi-lib-android-iso18013-data-transfer`). This README focuses on standalone
  usage.

The library is written in Kotlin and is available for Android.

## :heavy_exclamation_mark: Disclaimer

The released software is an initial development release version:

- The initial development release is an early endeavor reflecting the efforts of a
  short timeboxed period, and by no means can be considered as the final product.
- The initial development release may be changed substantially over time, might
  introduce new features but also may change or remove existing ones, potentially
  breaking compatibility with your existing code.
- The initial development release is limited in functional scope.
- The initial development release may contain errors or design flaws and other
  problems that could cause system or other failures and data loss.
- The initial development release has reduced security, privacy, availability, and
  reliability standards relative to future releases. This could make the software
  slower, less reliable, or more vulnerable to attacks than mature software.
- The initial development release is not yet comprehensively documented.
- Users of the software must perform sufficient engineering and additional testing
  in order to properly evaluate their application and determine whether any of the
  open-sourced components is suitable for use in that application.
- We strongly recommend not putting this version of the software into production use.
- Only the latest version of the software will be supported.

## Requirements

- Android 8 (API level 26) or higher

### Dependencies

To use snapshot versions, add the following to your project's settings.gradle file:

```groovy
dependencyResolutionManagement {
    repositories {
        // ...
        maven {
            url = uri("https://central.sonatype.com/repository/maven-snapshots/")
            mavenContent { snapshotsOnly() }
        }
        // ...
    }
}
```

To include the library in your project, add the following dependency to your
app's build.gradle file:

```groovy
dependencies {
    implementation "eu.europa.ec.eudi:eudi-lib-android-dcapi-manager:0.26.1"

    // Required runtime provider for the AndroidX Credentials Registry.
    // Without it, DCAPI registration fails with
    // "no provider dependencies found - please ensure the desired provider
    // dependencies are added" on all Android versions.
    implementation "androidx.credentials.registry:registry-provider-play-services:1.0.0-alpha04"
}
```

This module deliberately does **not** declare `registry-provider-play-services` as
a transitive dependency. The currently available runtime provider pulls in Google
Play Services, which is not available on every Android device — for example,
privacy-focused environments such as **GrapheneOS** intentionally ship without
GMS. By keeping the dependency optional, consumer apps choose whether to enable
DCAPI based on their target distribution.

## How to Use

The module exposes two main classes:

- `DCAPIManager` — the entry point for handling incoming credential requests
  delivered to your Activity through the system credential picker.
- `DCAPIIsoMdocRegistration` (and the underlying `IsoMdocRegistry`) — registers
  the wallet's mdoc credentials with the system so they become discoverable.

A wrapper, `DocumentManagerWithDCAPI`, is also provided to keep the registry in
sync automatically every time a document is stored or deleted.

### Declare the DCAPI Activity

In your application's `AndroidManifest.xml`, declare an Activity that listens for
the DCAPI intent filter:

```xml
<activity
    android:name=".MainActivity"
    android:exported="true">

    <!-- Required for DCAPI -->
    <intent-filter>
        <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
        <action android:name="androidx.identitycredentials.action.GET_CREDENTIALS" />

        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

### Registering credentials

Use `DCAPIIsoMdocRegistration` to push the current set of issued mdoc documents
to the system Credential Registry. The simplest way to keep the registry in sync
with the wallet is to wrap your `DocumentManager` with `DocumentManagerWithDCAPI`
— it triggers re-registration automatically whenever a document is stored or
deleted.

```kotlin
val documentManager: DocumentManager =
    TODO("The document manager that owns the wallet's documents")

val documentManagerWithDcapi = DocumentManagerWithDCAPI(
    delegate = documentManager,
    // dcapiRegistration is optional. If omitted, a default DCAPIIsoMdocRegistration
    // is created internally, using the application context.
)

// From this point on, any storeIssuedDocument / deleteDocumentById call on
// documentManagerWithDcapi will also update the system DCAPI registry in the
// background.
```

If you prefer to control the registration cycle yourself, instantiate
`DCAPIIsoMdocRegistration` directly:

```kotlin
val registration: DCAPIRegistration = DCAPIIsoMdocRegistration(
    context = applicationContext,
    documentManager = documentManager,
)

// Run on every change to your document set
lifecycleScope.launch {
    registration.registerCredentials()
}
```

You can also provide your own implementation of the `DCAPIRegistration` interface
if you need a custom registration strategy:

```kotlin
val customRegistration = DCAPIRegistration {
    // your own logic that ultimately calls
    // RegistryManager.create(context).registerCredentials(...)
}

val documentManagerWithDcapi = DocumentManagerWithDCAPI(
    delegate = documentManager,
    dcapiRegistration = customRegistration,
)
```

### Instantiating the DCAPIManager

`DCAPIManager` is responsible for processing incoming credential requests. It is
backed by a `DCAPIRequestProcessor` that decodes the `org-iso-mdoc` request,
matches it against the documents owned by the `DocumentManager`, and produces a
response.

```kotlin
val readerTrustStore: ReaderTrustStore = ReaderTrustStore.getDefault(
    trustedCertificates = listOf(
        // trustedReaderCertificate1,
        // trustedReaderCertificate2
    )
)

val privilegedAllowlist: String =
    // Either provide your own JSON allowlist of trusted browsers/apps, or use
    // the default one bundled with this library:
    context.getDefaultPrivilegedUserAgents()

val dcapiManager = DCAPIManager(
    requestProcessor = DCAPIRequestProcessor(
        documentManager = documentManager,
        readerTrustStore = readerTrustStore,
        privilegedAllowlist = privilegedAllowlist,
        zkSystemRepository = null,
    ),
)
```

### Handling the credential request in your Activity

When the user selects your wallet in the system credential picker, the system
launches the Activity declared with the DCAPI intent filter. Pass the incoming
`Intent` to `DCAPIManager.resolveRequest`:

```kotlin
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Hand the intent to the DCAPI manager, which extracts the
        // ProviderGetCredentialRequest internally and starts processing.
        dcapiManager.resolveRequest(intent)
    }
}
```

`resolveRequest(intent)` is a no-op when the intent does not contain a credential
request (e.g. when the activity was launched outside the DCAPI flow), so it is
safe to call unconditionally.

### Handling Transfer Events

`DCAPIManager` is event-driven. Attach a `TransferEvent.Listener` to receive
notifications about the request lifecycle:

```kotlin
dcapiManager.addTransferEventListener { event ->
    when (event) {
        is TransferEvent.RequestReceived -> try {
            // get the processed request
            val processedRequest = event.processedRequest.getOrThrow()

            // the request processing was successful
            // requested documents can be shown in the application
            val requestedDocuments = processedRequest.requestedDocuments
            // ...
            // application must create the DisclosedDocuments object
            val disclosedDocuments = DisclosedDocuments(
                // assume that the document is in mso_mdoc format
                DisclosedDocument(
                    documentId = "document-id",
                    disclosedItems = listOf(
                        MsoMdocItem(
                            namespace = "eu.europa.ec.eudi.pid.1",
                            elementIdentifier = "first_name"
                        ),
                    ),
                    // keyUnlockData is required if the document key is locked
                    // and needs to be unlocked to sign the response
                    keyUnlockData = TODO("provide key unlock data if needed"),
                ),
                // ... rest of the disclosed documents
            )
            // generate the response
            val response = processedRequest.generateResponse(
                disclosedDocuments = disclosedDocuments,
                signatureAlgorithm = Algorithm.ES256
            ).getOrThrow()

            dcapiManager.sendResponse(response)

        } catch (e: Throwable) {
            // An error occurred — handle it
        }

        is TransferEvent.IntentToSend -> {
            // The response intent is ready.
            // Set it as the activity result and finish() to return to the verifier.
            setResult(RESULT_OK, event.intent)
            finish()
        }

        is TransferEvent.Error -> {
            // An error has occurred during the DCAPI presentation.
            // If the error is a DCAPIException, you can convert it back to an
            // Intent that the system Credential Manager understands and return
            // it to the verifier.
            val error = event.error
            if (error is DCAPIException) {
                setResult(RESULT_OK, error.toIntent())
                finish()
            }
        }

        else -> { }
    }
}
```

The relevant events are:

- `TransferEvent.RequestReceived`: Indicates that a request has been received and
  processed. Get the processed request via `event.processedRequest`. The
  application can read the requested documents (`requestedDocuments`) and
  generate a response with `processedRequest.generateResponse(...)`.
- `TransferEvent.IntentToSend`: Indicates that the response intent
  (`event.intent`) is ready. Set it as the activity result and call `finish()`
  to return control to the verifier.
- `TransferEvent.Error`: Indicates that an error occurred. If `event.error` is a
  `DCAPIException`, you can call `error.toIntent()` to obtain an intent that
  surfaces the failure to the calling verifier.

### Privileged allowlist

DCAPI distinguishes between privileged callers (browsers running on behalf of a
website) and arbitrary apps. You can supply your own JSON allowlist via
`DCAPIRequestProcessor.privilegedAllowlist`. The expected format is:

```json
{
  "apps": [
    {
      "type": "android",
      "info": {
        "package_name": "com.example.app",
        "signatures": [
          {
            "build": "release",
            "cert_fingerprint_sha256": "59:0D:2D:7B:...:30:32"
          },
          {
            "build": "userdebug",
            "cert_fingerprint_sha256": "59:0D:2D:7B:...:30:32"
          }
        ]
      }
    }
  ]
}
```

If you don't need a custom list, the library bundles a default one that you can
load with `Context.getDefaultPrivilegedUserAgents()`.

### Logging

DCAPI classes accept an optional
`eu.europa.ec.eudi.wallet.dcapi.logging.Logger`. When `null` (the default),
nothing is logged. Provide your own implementation to route the records
wherever you want — Logcat, Timber, a file, a remote service, etc.

```kotlin
val logger = Logger { record ->
    val tag = record.sourceClassName ?: "DCAPI"
    when (record.level) {
        Logger.LEVEL_ERROR -> Log.e(tag, record.message, record.thrown)
        Logger.LEVEL_WARN -> Log.w(tag, record.message, record.thrown)
        Logger.LEVEL_INFO -> Log.i(tag, record.message)
        Logger.LEVEL_DEBUG -> Log.d(tag, record.message)
    }
}

val dcapiManager = DCAPIManager(
    requestProcessor = DCAPIRequestProcessor(..., logger = logger),
    logger = logger
)
```

When this module is consumed through `eudi-lib-android-wallet-core`, the
wallet-core's own `Logger` (configured via
`EudiWalletConfig.configureLogging(level = …)`) is wired in automatically — no
custom implementation needed.

## Using with EUDI Wallet Core

If you depend on `eudi-lib-android-wallet-core`, this module is brought in
transitively and you do **not** need to declare it explicitly. DCAPI is then
enabled and configured through `EudiWalletConfig.configureDCAPI { ... }`.

See [DIGITAL_CREDENTIAL_API.md](../DIGITAL_CREDENTIAL_API.md) for the full
wallet-core integration guide, including the manifest entry, configuration
options, and how to drive the presentation flow through `EudiWallet`.

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth
for everyone involved, follow the guidelines found in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## License

### Third-party component licenses

See [licenses.md](../licenses.md) for details.

### License details

Copyright (c) 2024 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
