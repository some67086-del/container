# AppStoreConnectClient

A small Swift client for the App Store Connect API, added from the supplied OpenAPI 4.4 specification.

## Authentication

Create an App Store Connect API key in App Store Connect and load the issuer ID, key ID, and the contents of the downloaded .p8 key at runtime. Do not commit the .p8 key to Git.

```swift
import AppStoreConnectClient

let credentials = AppStoreConnectCredentials(
    issuerID: ProcessInfo.processInfo.environment["ASC_ISSUER_ID"]!,
    keyID: ProcessInfo.processInfo.environment["ASC_KEY_ID"]!,
    privateKeyPEM: try String(contentsOfFile: ProcessInfo.processInfo.environment["ASC_PRIVATE_KEY_PATH"]!)
)

let client = AppStoreConnectClient(credentials: credentials)
let apps = try await client.apps()
let builds = try await client.builds(appID: apps.first?.id)
let groups = try await client.betaGroups(appID: apps.first?.id)
```

The client generates short-lived ES256 JWTs locally with CryptoKit and includes helpers for apps, builds, and TestFlight beta groups. The public `request` method can call additional endpoints from the OpenAPI specification.
