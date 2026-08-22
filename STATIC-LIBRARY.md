# Prebuilt static library

System Locker publishes a self-contained Windows x64 SDK for developers who
want to link Bedrock without building its third-party dependencies. The package
is built with Microsoft Visual C++, the static MSVC runtime, and static copies
of libcurl, OpenSSL Crypto, and zlib. It does not require Bedrock, curl,
OpenSSL, or zlib DLLs at runtime.

The current release archive is named
`systemlocker-bedrock-sdk-0.2.1-win64-static.zip` and is also available as the
`static/` directory in this repository.

The package is just headers, libraries, and license texts — it ships no build
system files. Link it from your existing build system (Visual Studio, Make,
CMake, or any other) the same way you would link any static library.

## Visual Studio integration

1. Add the SDK's `include` directory (`static/include` in this repository) to
   **Additional Include Directories**.
2. Add the SDK's `lib` directory (`static/lib` in this repository) to
   **Additional Library Directories**.
3. Use C++20 and target x64.
4. Select the static runtime: `/MT` for Release.
5. Add these libraries to **Additional Dependencies**, in this order:

```text
systemlocker_bedrock.lib
libcurl.lib
libcrypto.lib
zs.lib
bcrypt.lib
advapi32.lib
crypt32.lib
secur32.lib
ws2_32.lib
iphlpapi.lib
user32.lib
```

The published binary is a Release build. Applications that require a Debug
runtime build should compile the published source themselves with the matching
toolchain.

## Package contents

```text
include/       System Locker Bedrock public headers
lib/           Bedrock and bundled dependency libraries
licenses/      curl, OpenSSL, and zlib license texts
README.md
SECURITY.md
THIRD_PARTY_NOTICES.md
```

The package is supported for Windows x64 applications built with a compatible
Microsoft Visual C++ toolset. The source is also published in this repository
for embedding directly into projects on other platforms and toolchains.
