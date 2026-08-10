# System Locker Bedrock C++

![System Locker Logo](logo.png)

A C++20 reference client for System Locker's signed, session-based Bedrock
authentication protocol.

Bedrock treats every server response as hostile until its Ed25519 signature is
verified with the public key already pinned in the application. The library
then checks the response's challenge, system ID, protocol version, server time,
and identity hash before it can create or advance a session.

## Security properties

- Ed25519 verification happens over the exact response bytes before JSON is parsed.
- Signing keys are supplied locally by the developer; they are never learned from the authentication server.
- A fresh 64-byte cryptographic challenge is generated for every request.
- Successful heartbeat responses rotate the session token.
- Heartbeats are serialized inside the client to prevent accidental concurrency.
- A lost heartbeat response is retried once with the exact token and challenge so Bedrock can return its cached signed result.
- HTTPS certificate validation is mandatory. Optional curl SPKI pinning adds a second transport-layer check.
- License keys and passwords are not retained for heartbeats or persisted by the library.

No client-side library can stop an attacker who fully controls the process from
patching or replacing application code. Static linking, code signing, platform
hardening, and server-side policy should be used as complementary controls.

## Requirements

- CMake 3.20+
- A C++20 compiler
- libcurl
- OpenSSL 1.1.1 or newer (`Crypto` component)

OpenSSL is used for Ed25519, secure randomness, and SHA-256. nlohmann/json 3.11.3
is vendored as a private implementation dependency under `third_party/`.

The project-specific distribution terms should be published with the first
official release. The vendored dependency's MIT notice is included in
`THIRD_PARTY_NOTICES.md`.

## Build

With vcpkg on Windows:

```powershell
cmake -S . -B build `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

With system packages on Linux or macOS:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The exported CMake target is `SystemLocker::Bedrock`.

## Quick start

Download the public key from the System Locker dashboard through a trusted,
authenticated channel and embed its base64url value in your application.

```cpp
#include <syslocker/bedrock.hpp>

#include <iostream>

int main()
{
    syslocker::bedrock::Config config;
    config.systemId = "YOUR_20_CHAR_SYSTEM";
    config.version = "1.0.0";
    config.hwid = "YOUR-STABLE-HWID";
    config.signingPublicKey =
        "YOUR_BASE64URL_RAW_ED25519_PUBLIC_KEY";

    syslocker::bedrock::Client client(config);
    client.onHeartbeatFailure([](const auto &failure)
    {
        // Stop protected work and exit or return to a safe state.
        std::cerr << failure.error.message << '\n';
    });

    auto auth = client.authenticateWithKey("CUSTOMER-LICENSE-KEY");
    if (!auth)
    {
        // Transport, signature, freshness, or payload-integrity failure.
        std::cerr << auth.error().message << '\n';
        return 1;
    }
    if (!auth->sessionStarted)
    {
        // Authenticated server rejection such as INVALID_KEY.
        std::cerr << auth->response.responseCode << ": "
                  << auth->response.humanResponse << '\n';
        return 2;
    }

    while (client.isAuthenticated())
    {
        // Protected application work.
    }
}
```

`OUTDATED` is an authenticated, session-bearing response. Applications should
inspect `AuthenticationResult::response.code` and apply their own update
policy even when `sessionStarted` is true.

## Public-key rotation

Ship a replacement public key through your trusted application update channel
as part of a coordinated server-key rotation. A session retains the same
verified public key for its lifetime, so rotating the server key does not
interrupt an already-authenticated client. New processes must be configured
with the current public key.

Never download a signing key dynamically from the same unauthenticated server
response you are trying to verify.

## Manual and live testing

Set `Config::automaticHeartbeats = false` to call `Client::heartbeatNow()` from
your own scheduler. Calling it too early will correctly trigger the server's
terminal timing response.

An opt-in live probe is available without storing credentials in the repo:

```powershell
cmake -S . -B build-live `
  -DSYSLOCKER_BEDROCK_BUILD_LIVE_TEST=ON `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build-live --config Release --target systemlocker_bedrock_live_test

$env:SYSLOCKER_BEDROCK_SYSTEM_ID = "..."
$env:SYSLOCKER_BEDROCK_PUBLIC_KEY = "..."
$env:SYSLOCKER_BEDROCK_LICENSE_KEY = "..."
.\build-live\Release\systemlocker_bedrock_live_test.exe
```

The live probe is not registered with CTest and never prints the license key.

## Repository layout

```text
include/       stable public API
src/           implementation
tests/         offline protocol and tamper tests; optional live probe
examples/      environment-variable based CLI
docs/          protocol and implementation source notes
third_party/   vendored JSON parser and notice
publish/       separate sanitized public Git repository
```
