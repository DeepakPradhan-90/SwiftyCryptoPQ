#!/bin/bash
# Builds CryptoPQ.xcframework for iOS, the iOS Simulator, and macOS.
# The C implementation is linked into the CryptoPQ static framework, so a
# consumer only imports CryptoPQ.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-0.0.0}"
OUTPUT="${1:-"$ROOT/build/CryptoPQ.xcframework"}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

archive_one() {
  local destination="$1"
  local name="$2"
  echo "Archiving $name ($destination)"
  xcodebuild archive \
    -scheme SwiftyCryptoPQ \
    -destination "$destination" \
    -archivePath "$WORKDIR/$name.xcarchive" \
    -derivedDataPath "$WORKDIR/dd-$name" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    CODE_SIGNING_ALLOWED=NO \
    >"$WORKDIR/$name.log"
}

framework_plist() {
  local minimum="$1"
  local platform_key="$2"
  cat >"$3" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>CryptoPQ</string>
  <key>CFBundleIdentifier</key>
  <string>com.swiftycryptopq.CryptoPQ</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>CryptoPQ</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>${platform_key}</key>
  <string>${minimum}</string>
</dict>
</plist>
EOF
}

make_framework() {
  local name="$1"
  local minimum="$2"
  local platform_key="$3"
  local fw="$WORKDIR/fw-$name/CryptoPQ.framework"

  local object_dir
  object_dir="$(find "$WORKDIR/$name.xcarchive" -type d -name Objects -print -quit)"
  if [[ -z "$object_dir" || ! -f "$object_dir/CryptoPQ.o" || ! -f "$object_dir/CryptoPQC.o" ]]; then
    echo "Archive $name did not produce CryptoPQ.o and CryptoPQC.o" >&2
    exit 1
  fi

  local swiftmodule
  swiftmodule="$(find "$WORKDIR/dd-$name" -type d -name 'CryptoPQ.swiftmodule' -print -quit)"
  if [[ -z "$swiftmodule" ]]; then
    echo "Archive $name did not produce a CryptoPQ.swiftmodule" >&2
    exit 1
  fi

  mkdir -p "$fw/Modules"
  libtool -static -o "$fw/CryptoPQ" "$object_dir/CryptoPQ.o" "$object_dir/CryptoPQC.o"
  framework_plist "$minimum" "$platform_key" "$fw/Info.plist"

  local dest="$fw/Modules/CryptoPQ.swiftmodule"
  mkdir -p "$dest"
  # Library evolution clients need the public interface, not the package one.
  find "$swiftmodule" -type f \( \
    -name '*.swiftinterface' -o \
    -name '*.private.swiftinterface' -o \
    -name '*.swiftmodule' -o \
    -name '*.swiftdoc' \
  \) ! -name '*.package.swiftinterface' -exec cp {} "$dest/" \;
}

archive_one "generic/platform=iOS" ios
archive_one "generic/platform=iOS Simulator" iossim
archive_one "generic/platform=macOS" macos

make_framework ios "15.0" MinimumOSVersion
make_framework iossim "15.0" MinimumOSVersion
make_framework macos "11.0" LSMinimumSystemVersion

rm -rf "$OUTPUT"
mkdir -p "$(dirname "$OUTPUT")"
xcodebuild -create-xcframework \
  -framework "$WORKDIR/fw-ios/CryptoPQ.framework" \
  -framework "$WORKDIR/fw-iossim/CryptoPQ.framework" \
  -framework "$WORKDIR/fw-macos/CryptoPQ.framework" \
  -output "$OUTPUT"

echo "Created $OUTPUT"
