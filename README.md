# System Locker Bedrock C++

![System Locker Logo](logo.png)

A C++20 reference client for System Locker's signed, session-based Bedrock
authentication protocol.

Bedrock treats every server response as hostile until its Ed25519 signature is
verified with the public key already pinned in the application. The library
then checks the response's challenge, system ID, protocol version, server time,
and identity hash before it can create or advance a session.

The repository is a source-only distribution. There are two ways to integrate
the library into your own project:

1. **Integrate the source directly** — recommended. Copy `include/` and `src/`
   into your project and compile them as part of your own build.
2. **Link the prebuilt static package** in `static/` — the fastest setup when
   you prefer a ready-made static library for Windows x64.

The library is provided for your convenience above all else. Compiling the
implementation directly into your own binary keeps your existing build flags
and lets you step through the source in your own build; the prebuilt package is
there when you want a quick, known-good link.

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

Integrating the source directly requires:

- A C++20 compiler (Visual Studio 2019 16.8+ / 2022, GCC 11+, Clang 14+, or AppleClang 14+)
- libcurl
- OpenSSL 1.1.1 or newer (`Crypto` component)

OpenSSL is used for Ed25519, secure randomness, and SHA-256. nlohmann/json 3.11.3
is vendored as a private implementation dependency under `third_party/`.

The prebuilt static SDK additionally requires Windows x64 and a compatible
Microsoft Visual C++ toolset. It already contains Bedrock's compiled
third-party dependencies. See [STATIC-LIBRARY.md](STATIC-LIBRARY.md).

Dependency notices are included in `THIRD_PARTY_NOTICES.md`, with complete
license texts alongside the prebuilt SDK.

## Prebuilt static SDK

The repository's `static/` directory and the matching release archive provide
a ready-to-link, fully static Bedrock SDK for Windows x64. It already contains
Bedrock, libcurl, OpenSSL Crypto, and zlib compiled with the static `/MT`
runtime, so no Bedrock or dependency DLL is required.

The package is just headers, libraries, and license texts — it ships no build
system files. Link it through your existing build system (for example the
Visual Studio steps in [STATIC-LIBRARY.md](STATIC-LIBRARY.md)) the same way
you would link any other static library.

## Integrate the source directly (recommended)

Use this when you want to compile System Locker Bedrock into your own project
instead of linking a prebuilt library.

### Files to copy into your project

At minimum, bring these into your project or vendor directory:

```text
include/syslocker/
src/
third_party/nlohmann/json.hpp
```

### Files that must be compiled

Add every `.cpp` under `src/` to your project and keep the private headers from
`src/` beside them:

```text
bedrock.cpp
crypto.cpp
curl_http.cpp
response.cpp
```

### Visual Studio setup

1. Set your project to C++20.
2. Add `src/*.cpp` to your project and keep `src/crypto.hpp` beside them.
3. Add `include/` to C/C++ -> General -> Additional Include Directories.
4. Add `third_party/nlohmann/` to C/C++ -> General -> Additional Include Directories.
5. Add your libcurl, OpenSSL Crypto, and zlib libraries, plus the Windows SDK
   libraries, to Linker -> Input -> Additional Dependencies:

```text
libcurl.lib;libcrypto.lib;zs.lib;bcrypt.lib;advapi32.lib;crypt32.lib;secur32.lib;ws2_32.lib;iphlpapi.lib;user32.lib
```

The exact curl and OpenSSL library names depend on how you provide them (vcpkg,
system packages, or a bundled build).

### Minimal include

```cpp
#include <syslocker/bedrock.hpp>
```

### Other build systems

The library has no build system files of its own. Integrate it the same way in
any build system: compile `src/*.cpp`, add `include/` and
`third_party/nlohmann/` to the include path, and link libcurl, OpenSSL Crypto,
and zlib. Because `SYSLOCKER_BEDROCK_SHARED` is never defined, the headers use
plain static linkage.

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

## Manual heartbeat scheduling

Set `Config::automaticHeartbeats = false` to call `Client::heartbeatNow()` from
your own scheduler. Calling it too early will correctly trigger the server's
terminal timing response.

## Repository layout

```text
include/       stable public API
src/           implementation
tests/         offline protocol and tamper tests (reference)
examples/      environment-variable based CLI (reference)
third_party/   vendored JSON parser and notice
static/        prebuilt Windows x64 static SDK and release archive
```
