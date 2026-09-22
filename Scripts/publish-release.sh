#!/bin/bash
# Publishes a GitHub release containing CryptoPQ.xcframework, and a semver tag
# whose Package.swift is a binary target pointing at that release asset.
# Swift Package Manager resolves version tags to this binary package. The
# source package remains on main.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

REMOTE="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

if gh release list --limit 200 --json body --jq ".[].body" | grep -F "Source-SHA: ${GITHUB_SHA}" >/dev/null; then
  echo "Release already exists for ${GITHUB_SHA}"
  exit 0
fi

VERSION="$(python3 - <<'PY'
import subprocess
tags = subprocess.check_output(["git", "tag", "-l"], text=True).split()
versions = []
for tag in tags:
    bare = tag[1:] if tag.startswith("v") else tag
    parts = bare.split(".")
    if len(parts) == 3 and all(part.isdigit() for part in parts):
        versions.append(tuple(int(part) for part in parts))
if not versions:
    print("1.0.0")
else:
    major, minor, patch = max(versions)
    print(f"{major}.{minor}.{patch + 1}")
PY
)"

echo "Releasing ${VERSION} from ${GITHUB_SHA}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

VERSION="$VERSION" Scripts/make-xcframework.sh "$STAGE/CryptoPQ.xcframework"
ditto -c -k --keepParent "$STAGE/CryptoPQ.xcframework" "$STAGE/CryptoPQ.xcframework.zip"
CHECKSUM="$(swift package compute-checksum "$STAGE/CryptoPQ.xcframework.zip")"
URL="https://github.com/${GITHUB_REPOSITORY}/releases/download/${VERSION}/CryptoPQ.xcframework.zip"

cat >"$STAGE/Package.swift" <<EOF
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftyCryptoPQ",
    platforms: [
        .iOS(.v15),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "CryptoPQ",
            targets: ["CryptoPQ"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "CryptoPQ",
            url: "${URL}",
            checksum: "${CHECKSUM}"
        )
    ]
)
EOF

NOTES="$STAGE/notes.md"
cat >"$NOTES" <<EOF
Precompiled CryptoPQ ${VERSION}.

\`\`\`swift
.package(url: "https://github.com/${GITHUB_REPOSITORY}.git", from: "${VERSION}")
\`\`\`

The \`${VERSION}\` tag is a Swift package whose only target is this XCFramework. Source builds stay on the \`main\` branch.

Source-SHA: ${GITHUB_SHA}
EOF

GIT="$STAGE/git"
git init -b binary "$GIT"
cd "$GIT"
if git fetch "$REMOTE" binary; then
  git checkout -B binary FETCH_HEAD
fi
cp "$STAGE/Package.swift" "$ROOT/LICENSE" .
git add -A
git -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -m "Release CryptoPQ ${VERSION} binary package"
git tag "$VERSION"
git push "$REMOTE" HEAD:refs/heads/binary
git push "$REMOTE" "refs/tags/${VERSION}"

gh release create "$VERSION" "$STAGE/CryptoPQ.xcframework.zip" \
  --repo "$GITHUB_REPOSITORY" \
  --title "$VERSION" \
  --notes-file "$NOTES" \
  --target "$VERSION"

echo "Published ${VERSION}"
