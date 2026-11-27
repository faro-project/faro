# Faro for Android

The Android app: a Kotlin shell around the Rust core in `crates/faro-android` (UniFFI, package
`org.faro.core`). Design: `docs/ARCHITECTURE.md` section 3 (process model, tamper table) and
section 12 (never invisible). **This project has not been built yet**: it was written without a
Gradle, NDK or cargo-ndk on the machine. The first build may need small fixes.

## What it does

- `FaroAccessibilityService` takes screenshots on request (`takeScreenshot`, Android 11+), reads
  which app is in front and the address bar of known browsers (reduced to `scheme://host/` by
  `OriginReducer` before it leaves Kotlin), and notes when the person last touched the screen.
- `MonitorService` is a foreground service with a persistent notification ("This device is monitored
  by Faro..."). It runs the Rust core, starts at boot and after an update, and tells the core when
  the screen locks or wakes. The notification has no stop or pause action.
- `FaroDeviceAdminReceiver` makes removing Faro never silent: asking to turn it off, and turning it
  off, tell the member's allies first. It asks for no device policies.
- `EnrollActivity` (a `faro://enroll?...` link, or an address and a code) and `SetupActivity`
  (notifications, Accessibility, device protection, battery) enroll the phone and switch on what it needs.
- `StatusActivity` shows state only, like the desktop status menu. `NoticeActivity` shows a notice
  from Faro as a full-screen window with an OK button.

Nothing in the app can stop, pause or hide monitoring. No screenshot, title or address is written to
disk or logged.

Not done yet: QR scanning for enrollment (paste the link), Android Keystore wrapping of the device
key (keys are files in `noBackupFilesDir/faro`), a release signing setup.

## Prerequisites

- JDK 17 or newer.
- Android SDK with `platforms;android-35` and build-tools (`ANDROID_HOME` set).
- Android NDK r30 (`ndk;30.0.16248370`). Recent command-line tools replace `sdkmanager` with `android sdk install ndk/30.0.16248370`; `build-android.sh` finds it under `ANDROID_HOME/ndk/` or through `ANDROID_NDK_HOME`.
- Rust with the Android targets: `rustup target add aarch64-linux-android x86_64-linux-android`.
- `cargo install cargo-ndk`.
- Nothing for Gradle: the committed wrapper (`./gradlew`) downloads Gradle 8.10.2 and checks its checksum.
- Git Bash on Windows. The Gradle build runs `crates/faro-android/build-android.sh` with Git Bash's `bash.exe` (not WSL's); `-Pfaro.bash=<path>` picks another shell.

## Build and install a debug APK

```sh
cd apps/android
./gradlew :app:testDebugUnitTest      # the pure-Kotlin tests (OriginReducer and friends)
./gradlew :app:assembleDebug          # builds the Rust core too
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The task `buildFaroCore` runs `crates/faro-android/build-android.sh build/generated/faro`. That
writes `jniLibs/<abi>/libfaro_android.so` and `kotlin/` (the UniFFI bindings); the build adds them as
the `jniLibs` and Kotlin source directories. To use a core somebody already built, pass
`-Pfaro.generatedDir=<dir>` (a directory with `jniLibs/` and `kotlin/`, relative to `apps/android`).

## Setting up a phone

1. Install the APK and open Faro.
2. In your Faro web app open Computers, add a device and copy the link. In Faro choose
   "Enroll this phone", paste the link (or the address and the code), and check the instance name.
3. Compare the code Faro shows with the one in the web app, and approve the device there.
4. Follow the setup steps:
   - Allow notifications (Android 13 and later).
   - Turn on Faro in Accessibility. Faro isn't from the Play Store, so on Android 13 and later the switch
     can be greyed out as a "restricted setting". Open Settings, Apps, Faro, tap the three-dot menu and
     choose **Allow restricted settings** (the menu appears after you have tried to switch it on once),
     then switch Faro on.
   - Turn on device protection (device administrator), so that removing Faro is never silent.
   - Stop battery saving for Faro.

## Tests

`app/src/test` has JVM unit tests for the logic with no Android dependency: `OriginReducer`,
`BrowserAddressBars`, `FrameMath`, `SecureWindowPolicy`, `TamperQueue`, `SetupSteps`, `EnrollLink`.
They need the generated Kotlin to compile (the whole module builds together), so they run after the
core is built: `./gradlew :app:testDebugUnitTest`.

## CI runner

`.github/workflows/android.yml` runs on `[self-hosted, macOS, ARM64]` (Google ships no NDK for Linux
ARM64) on manual dispatch and on pull requests that touch `apps/android/**` or `crates/faro-android/**`.
That runner needs, before the job can pass:

- a JDK 17 or newer on `PATH`;
- the Android SDK (`platforms;android-35`, build-tools) at `ANDROID_HOME`, with licences accepted;
- the NDK `ndk;30.0.16248370` at `ANDROID_NDK_HOME`;
- network access to Google's Maven (`dl.google.com`) and Maven Central for Gradle dependencies.

Rust, cargo-ndk and Gradle are installed by the job itself. The Gradle version is set in the
workflow because no wrapper jar is committed.
