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
| `data/` | Share configuration, validation, and persistence |
| `ui/MainScreen.kt` | Compose UI |
