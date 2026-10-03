# Easy SMB

A lightweight Android app that uses [Shizuku](https://shizuku.rikka.app/) to share a local
folder over SMB, with a single screen for configuring and managing the server.

## Connecting

Turn the server on, then connect from another device on the same Wi-Fi with the address the app
shows (for example `smb://192.168.1.20:4445/share`) and the username and password you set.

- **Linux:** `smbclient //192.168.1.20/share -p 4445 -U alice`, or
  `mount -t cifs //192.168.1.20/share /mnt -o port=4445,username=alice`, or `smb://…` in the file
  manager.
- **macOS:** Finder → Go → Connect to Server → `smb://192.168.1.20:4445/share`.
- **Android:** any SMB2/3 file manager or media player that lets you set the port.
- **Windows 11 24H2 or newer:** `net use Z: \\192.168.1.20\share /TCPPORT:4445 /USER:alice`.
  Older Windows versions can only use port 445, which the shell uid can't bind.

## How it works

- The app binds a Shizuku *user service* (`ShareService`) that runs in its own process as the
  shell uid (or root, if Shizuku was started with root). That process does the file access and
  hosts the SMB server, so the app itself needs no storage permissions.
- The service runs as a daemon: it keeps serving after the app is closed, and is removed when
  the server is stopped.
- Because the shell uid can't bind ports below 1024, the server uses a custom port
  (default `4445`). Clients connect with e.g. `smb://<phone-ip>:4445/share`.

## Features

- One shared folder, optionally read-only
- SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1, including clients that start with an SMB1 negotiate
- NTLMv2 authentication (raw or via SPNEGO) against the configured user; anonymous, guest and
  NTLMv1 logons are rejected, and repeated failures are slowed down and disconnected
- Message signing is required (HMAC-SHA256 for 2.x, AES-CMAC for 3.x, with the 3.1.1
  pre-authentication integrity hash)
- Browse, read, write, create, rename, delete, truncate, set timestamps, file-system size and
  attribute queries, compound requests, and share listing through `srvsvc` on `IPC$`
- Not supported: encryption, durable handles, oplocks/leases, byte-range locks (granted without
  enforcement), named streams, and change notifications (requests stay pending until cancelled)

## Settings and security

- The share password is encrypted with an AES-GCM key held in the Android Keystore; it is
  decrypted only to hand it to the Shizuku service when the server starts.
- The app remembers whether the server was left on. On launch it reconnects to the running
  service, or restarts it if the service process was killed (for example, Shizuku restarted).
  If the server is off, opening the app does not start any background process.

## SMB server module

The server lives in a separate pure Kotlin/JVM module (`:smb`, package
`app.shizuku.smb.server`) with no Android dependencies, so it is developed and tested on a desktop
JVM. `ShareService` only creates, starts and stops it.

**Safety**

- Every client path is resolved against the share root: `..` is rejected, and symlinks whose
  target is outside the share can't be opened and are hidden from listings.
- Read-only shares refuse every operation that changes data, at open time and again per request.
- Message sizes, sessions, tree connects, open handles and connections are capped; connections
  that don't authenticate within 30 seconds, or stay idle for 15 minutes, are dropped.
- Passwords and keys are never logged.

**Testing**

`SmbServerTest` starts the server on a random port and drives it with
[smbj](https://github.com/hierynomus/smbj), an independent SMB client: every dialect, login and
wrong-password rejection, listing (including large folders), read, write, rename, delete,
read-only enforcement and path-escape attempts. `CryptoTest` checks MD4, AES-CMAC and RC4 against
published test vectors and runs an NTLMv2 exchange. The server has also been checked by hand with
`smbclient` (all dialects, share listing, recursive put/get/deltree) and impacket.

## Requirements

- Android 8.0 (API 26) or newer
- Shizuku installed and running

## Building

```sh
./gradlew assembleDebug
./gradlew testDebugUnitTest :smb:test
```

Requires JDK 17+ and the Android SDK (platform 35). CI builds the debug APK on every push.

## Project layout

| Path | Purpose |
| --- | --- |
| `app/src/main/aidl/.../IShareService.aidl` | Binder interface between the app and the Shizuku service |
| `service/ShareService.kt` | Shizuku user service that hosts the SMB server |
| `shizuku/ShizukuManager.kt` | Shizuku availability, permission, and service binding |
| `data/` | Share configuration, validation, persistence, and Keystore encryption |
| `ui/MainScreen.kt` | Compose UI |
| `smb/` | The SMB 2/3 server (pure Kotlin/JVM) and its tests |
