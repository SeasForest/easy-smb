# Easy SMB

A lightweight Android app that uses [Shizuku](https://shizuku.rikka.app/) to share a local
folder over SMB, with a single screen for configuring and managing the server.

> **Status:** project scaffold. The Shizuku integration, settings and UI are in place; the SMB
> protocol server is not implemented yet. Starting the server currently checks that the folder
> is accessible and the port can be bound from the Shizuku process, then reports the result.

## How it works

- The app binds a Shizuku *user service* (`ShareService`) that runs in its own process as the
  shell uid (or root, if Shizuku was started with root). That process does the file access and
  will host the SMB server, so the app itself needs no storage permissions.
- The service runs as a daemon: it keeps serving after the app is closed, and is removed when
  the server is stopped.
- Because the shell uid can't bind ports below 1024, the server uses a custom port
  (default `4445`). Clients connect with e.g. `smb://<phone-ip>:4445/share`.

## v1 scope

- One shared folder, optionally read-only
- Custom port, username/password authentication
- Basic file operations for Linux, macOS and Android clients
- Later: Windows 11 alternate-port support (`net use \\host\share /TCPPORT:4445`)

## Settings and security

- The share password is encrypted with an AES-GCM key held in the Android Keystore; it is
  decrypted only to hand it to the Shizuku service when the server starts.
- The app remembers whether the server was left on. On launch it reconnects to the running
  service, or restarts it if the service process was killed (for example, Shizuku restarted).
  If the server is off, opening the app does not start any background process.

## Roadmap: SMB server module

Planned next step. The server goes in a separate pure Kotlin/JVM module (`:smb`) with no Android
dependencies, so it can be developed and tested on a desktop JVM. `ShareService` only creates,
starts and stops it.

**Module API (sketch)**

- `SmbServer(config, root: File)` with `start()`, `stop()`, and a status/connection-count callback
  that `ShareService` exposes through `IShareService`.
- `config` reuses the existing fields: share name, port, username, password, read-only.

**Protocol scope for v1**

- SMB 2.1 and 3.1.1 dialects over TCP on the configured port.
- NTLMv2 authentication (via SPNEGO) against the single configured user; anonymous and guest
  sessions rejected.
- Message signing, since current clients expect or require it.
- File operations: directory listing, open/create, read, write, flush, close, rename, delete
  (files and empty folders), query and set basic file information, and file-system size info.
- Read-only shares reject every operation that modifies data.

**Safety requirements**

- Resolve every client path against the share root and reject anything that escapes it,
  including `..` segments and symlinks pointing outside the root.
- Cap message sizes, open handles, and connections per client; drop idle and unauthenticated
  connections after a timeout.
- Never log passwords or session keys.

**Testing**

- JVM integration tests that start the server on a random port and connect with an
  independent SMB client library: login, wrong-password rejection, list, read, write, rename,
  delete, read-only enforcement, and path-escape attempts.
- Manual checks with `smbclient` (Linux), Finder (macOS) and an Android file manager.

**Later**

- Windows 11 alternate-port connections (`net use \\host\share /TCPPORT:4445`).
- Multiple shares.

## Requirements

- Android 8.0 (API 26) or newer
- Shizuku installed and running

## Building

```sh
./gradlew assembleDebug
./gradlew testDebugUnitTest
```

Requires JDK 17+ and the Android SDK (platform 35). CI builds the debug APK on every push.

## Project layout

| Path | Purpose |
| --- | --- |
| `app/src/main/aidl/.../IShareService.aidl` | Binder interface between the app and the Shizuku service |
| `service/ShareService.kt` | Shizuku user service; will host the SMB server |
| `shizuku/ShizukuManager.kt` | Shizuku availability, permission, and service binding |
| `data/` | Share configuration, validation, persistence, and Keystore encryption |
| `ui/MainScreen.kt` | Compose UI |
