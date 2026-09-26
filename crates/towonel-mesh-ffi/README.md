# towonel-mesh-ffi

UniFFI bindings over `towonel-mesh` for the mobile apps. The Rust side owns
enrollment, the peer layer and routing; the app owns the OS VPN interface and
moves IP packets in and out.

## API

One object, `Mesh(stateDir)`, plus a `MeshListener` the app implements.

- `enrollment()`: the saved enrollment, no network.
- `enrollWithAuthKey(hubUrl, authKey, name)`
- `requestSignIn(hubUrl, name)` → code + verification URL (show a QR code),
  then `waitForSignIn()`. Also renews an expired key.
- `start(listener)` / `stop()`
- `sendPacket(bytes)`: a packet read from the VPN interface.
- `listener.onPacket(bytes)`: a packet to write to the VPN interface.
- `listener.onPeersChanged(peers)`, `listener.onStopped(reason)`
- `peers()`, `dnsDomain()`, and the free function `resolver()`

Async calls are `suspend fun` in Kotlin and `async throws` in Swift. Errors
are `MeshException` / `MeshError`: `NotEnrolled`, `KeyExpired` (sign in again),
`Removed`, `CodeExpired`, `Other`. Listener methods are called from
background threads.

The VPN interface should use MTU 1280 and route `100.64.0.0/10` plus the
device's IPv6 /48 (from `enrollment().ipv6`). For names, set its DNS server
to `resolver()` for `dnsDomain()` only (Android `addDnsServer` +
`addSearchDomain`, iOS `NEDNSSettings.matchDomains`).

## Build

```sh
make mesh-android    # target/{aarch64,x86_64}-linux-android/release/libtowonel_mesh_ffi.so
make mesh-bindings   # target/bindings/{kotlin,swift}
```

Android: copy the `.so` files to `jniLibs/arm64-v8a` and `jniLibs/x86_64`,
add the generated Kotlin file, and depend on JNA (`net.java.dev.jna:jna`,
`@aar`). Needs `ANDROID_NDK_HOME`; min API 26.

iOS / macOS (not built yet; needs Xcode):

```sh
cargo build --release -p towonel-mesh-ffi --target aarch64-apple-ios
cargo build --release -p towonel-mesh-ffi --target aarch64-apple-ios-sim
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libtowonel_mesh_ffi.a -headers target/bindings/swift \
  -library target/aarch64-apple-ios-sim/release/libtowonel_mesh_ffi.a -headers target/bindings/swift \
  -output TowonelMesh.xcframework
```

The Network Extension reads packets from `NEPacketTunnelFlow` into
`sendPacket` and writes `onPacket` back to it.

## Desktop

A Rust desktop app (e.g. Tauri) can use `towonel-mesh` directly. Alternatively
it can drive a running `towonel mesh up` through the local socket
(`towonel_mesh::local`, Unix only for now).
