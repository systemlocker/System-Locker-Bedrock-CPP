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

### Fault-tolerant HWID (SL-HWID)

SL-HWID is available in 1.0.0 as an opt-in device identifier. It is fault
tolerant, cross platform (Windows, macOS, Linux), and combines **14 hardware
factors**: any two can fail or change without changing the HWID, and drifted
factors are quietly re-absorbed after each successful authentication. The
point is to prevent over-fitting to any single machine detail while avoiding
over-dependence on the exact hardware configuration.

#### Upgrading an existing application

**If you enables SL-HWID, reset every existing HWID for the system
after deploying 1.0.0 and before affected users authenticate.** SL-HWID
intentionally produces a different opaque identifier from the pre-1.0
identifier, so existing device claims would otherwise be rejected as an HWID
mismatch. Use the dashboard's reset-all-HWIDs action (or your existing
administrative reset-every-HWID workflow), then let each user authenticate to
claim their new identifier.

This reset is required only when you opt into SL-HWID. Keep existing claims
when continuing to send a custom identifier or the legacy identifier.

For this C++ library, `Config::hwid` defaults to `"1"`, which leaves device
locking disabled. To opt in, set `Config::hwid` to an empty string and retain
the default `Config::hwidMode = "sl-hwid"`. Set `Config::hwidMode = "legacy"`
to use the pre-1.0 derivation instead. Any non-empty custom `Config::hwid`
still takes precedence over the mode.

Default storage is shared by all Bedrock applications for the current user,
so they report the same HWID on the same device. A short-lived interprocess
lock serializes enrollment and refresh; a crashed process's marker is
recovered automatically. Configure a different `Config::slHwidStore` only
when you deliberately need separate device state. Re-enrolling changes the
HWID for every application sharing that storage.

The HWID determination is deliberately best-effort, but it is expected to
match runs of the same application, and, in most cases, across any
application run on the same device and operating system.

Storage lives in the Windows registry (`HKLM\SOFTWARE\SystemLocker`, with
an HKCU fallback) and a per-user directory elsewhere. One factor — the
module's own persisted value — is hard-locked: changing or deleting it
always requires re-activation, since that is tampering rather than drift.
Name additional hard-locked factors with `Config::slHwidExtraMandatory` (for example
`machine_guid`).

A hard lock chosen when the shared device state is enrolled cannot be
weakened by another application.

## Security properties

- Ed25519 verification happens over the exact response bytes before JSON is parsed.
- Signing keys are supplied locally by the developer; they are never learned from the authentication server.
- A fresh 64-byte cryptographic challenge is generated for every request.
- Successful heartbeat responses rotate the session token.
- Heartbeats are serialized inside the client to prevent accidental concurrency.
- A lost heartbeat response is retried once with the exact token and challenge so Bedrock can return its cached signed result.
- HTTPS certificate validation is mandatory. Optional curl SPKI pinning adds a second transport-layer check.
- License keys and passwords are not retained for heartbeats or persisted by the library.
- Requested variables and Invisible Folder tokens are read only after the signed Bedrock response verifies.

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
invisible_folder.cpp
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

## Variables and Invisible Folder

Request server-side variables and an Invisible Folder Advanced token during
initialization. Missing variables are represented as `std::nullopt`, matching
Bedrock's signed JSON value of `false`.

```cpp
syslocker::bedrock::InitializationOptions options;
options.requestInvisibleFolderToken = true;
options.variables = {"release_channel", "message_of_the_day"};

auto auth = client.authenticateWithKey("CUSTOMER-LICENSE-KEY", options);
if (!auth || !auth->sessionStarted)
    return 1;

const auto channel = auth->response.variables.at("release_channel");
if (channel)
    std::cout << *channel << '\n';
```

When a running session needs a new Advanced token, request it with a manually
scheduled heartbeat. The token stays in memory and is cleared at shutdown.

```cpp
auto heartbeat = client.heartbeatNow({.requestInvisibleFolderToken = true});
if (!heartbeat)
    return 1;
```

`Config::invisibleFolderApiKey` and the Bedrock token have deliberately
different jobs:

| File permission        | Metadata credential                                              | Bedrock helper download               |
| ---------------------- | ---------------------------------------------------------------- | ------------------------------------- |
| System Locker Advanced | Short-lived `invisible_folder_token` / `X-Invisiblefolder-Token` | Yes, uses the in-memory Bedrock token |
| API Available          | Invisible Folder API key                                         | Metadata only                         |
| Password Protected     | Invisible Folder API key with `downloads.password_protected`     | Metadata only                         |
| System Locker Simple   | Invisible Folder API key with `downloads.system_locker_simple`   | Metadata only                         |

Advanced metadata intentionally rejects an API key, even one with an Advanced
download scope. Conversely, API-key metadata cannot use the Bedrock token.
The library sends both configured credentials to the metadata endpoint; the
server selects the valid one from the file's effective permission.

For updates, `downloadIfNew` first reads `__revisions`. Passing a known
revision skips an unchanged file; omit a destination to receive newer bytes in
memory, or provide a destination selected by the application to save them.

```cpp
auto update = client.invisibleFolder().downloadIfNew(
    "release-reference",
    "17",
    std::filesystem::path{"C:/ProgramData/Example/release.bin"});
if (!update)
    return 1;
if (update->downloaded)
    std::cout << "Saved revision " << update->revision << '\n';
```

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` authentication for such an account is
answered with a signed `GOOGLE_SSO_REQUIRED` denial whose payload carries
`sso_url` — the portal where the user completes Google sign-in and receives
a system-specific password (valid 180 days) to use as their account
password. There is no callback; the user transcribes the generated password
into your login form and you simply retry.

```cpp
const auto auth = client.authenticateWithPassword(username, password);
if (auth && auth->response.code == ResponseCode::GoogleSsoRequired)
{
    // The denial's URL is authoritative; open it in the default browser.
    std::string portal = auth->response.ssoUrl.value_or(client.googleSsoUrl());
    if (!openUrl(portal))
        std::cout << "Finish Google sign-in at: " << portal << std::endl; // headless fallback
}
```

You can also start the flow before any denial: `client.beginGoogleSso()`
(or `beginGoogleSso(systemId)`) opens the portal and returns an
`SsoLaunch{ url, opened }`.

## Repository layout

```text
include/       stable public API
src/           implementation
examples/      environment-variable based CLI (reference)
third_party/   vendored JSON parser and notice
static/        prebuilt Windows x64 static SDK and release archive
```
