#!/bin/bash
# Publishes a GitHub release containing CryptoPQ.xcframework, and a semver tag
# whose Package.swift is a binary target pointing at that release asset.
# Swift Package Manager resolves version tags to this binary package. The
# source package remains on main.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

REMOTE="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

# Paths that can change what a consumer receives: the library, the vendored C
# and its patches, the manifest, the script that builds the framework, and the
# notices shipped alongside it. A merge touching none of these produces a
# byte-for-byte equivalent package, so it is not worth a version number.
#
# This is an allowlist rather than a list of things to ignore, so that a path
# nobody thought about does not quietly publish a release. The cost is that a
# new source location has to be added here, which the skip message makes
# obvious by naming the files it disregarded.
RELEVANT='^(Sources/|patches/|Package\.swift$|Scripts/make-xcframework\.sh$|LICENSE$|NOTICE$)'

note() {
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "$1" >>"$GITHUB_STEP_SUMMARY"
  fi
}

# Newest first, so the first Source-SHA is the commit the last release was
# built from. GitHub returns these bodies with CRLF line endings, which would
# otherwise defeat the anchored match below.
RELEASE_BODIES="$(gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=100" --jq '.[].body' | tr -d '\r')"

if printf '%s\n' "$RELEASE_BODIES" | grep -Fq "Source-SHA: ${SOURCE_SHA}"; then
  note "Release already exists for ${SOURCE_SHA}."
  exit 0
fi

RELEASED_SHA="$(printf '%s\n' "$RELEASE_BODIES" |
  sed -n 's/^Source-SHA: \([0-9a-f]\{40\}\)$/\1/p' | head -1)"

# With no previous release there is no baseline to compare against, and the
# first release has to happen regardless. A baseline that is missing from the
# history, after a force push say, is treated the same way.
if [ -n "$RELEASED_SHA" ] && git cat-file -e "${RELEASED_SHA}^{commit}" 2>/dev/null; then
  CHANGED="$(git diff --name-only "$RELEASED_SHA" "$SOURCE_SHA")"
  if ! printf '%s\n' "$CHANGED" | grep -qE "$RELEVANT"; then
    note "No release: nothing that affects the published package changed since ${RELEASED_SHA}. Disregarded $(printf '%s' "$CHANGED" | tr '\n' ' ')"
    exit 0
  fi
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

if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null || \
   git ls-remote --exit-code --tags "$REMOTE" "refs/tags/${VERSION}" >/dev/null 2>&1; then
  echo "Tag ${VERSION} already exists" >&2
  exit 1
fi

echo "Releasing ${VERSION} from ${SOURCE_SHA}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

VERSION="$VERSION" Scripts/make-xcframework.sh "$STAGE/CryptoPQ.xcframework"
Scripts/verify-xcframework.sh "$STAGE/CryptoPQ.xcframework"

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

The \`${VERSION}\` tag is a Swift package whose only target is this XCFramework, built for iOS, the iOS Simulator, and macOS. Source builds stay on the \`main\` branch.

Source-SHA: ${SOURCE_SHA}
EOF

# The binary package lives on its own branch so that main stays buildable from
# source and the tag still resolves to a Package.swift.
GIT="$STAGE/git"
git init -q -b binary "$GIT"
cd "$GIT"
if git ls-remote --exit-code --heads "$REMOTE" binary >/dev/null 2>&1; then
  git fetch -q "$REMOTE" binary
  git checkout -q -B binary FETCH_HEAD
fi
# Apache 2.0 section 4(d) requires the NOTICE file to travel with
# redistributions, and the binary package is a redistribution.
cp "$STAGE/Package.swift" "$ROOT/LICENSE" "$ROOT/NOTICE" .
git add -A
git -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -q -m "Release CryptoPQ ${VERSION} binary package"
git push -q "$REMOTE" HEAD:refs/heads/binary
BINARY_SHA="$(git rev-parse HEAD)"

# Creating the release also creates the tag, so a partial publish cannot leave
# a version tag that Swift Package Manager resolves to a missing asset.
gh release create "$VERSION" "$STAGE/CryptoPQ.xcframework.zip" \
  --repo "$GITHUB_REPOSITORY" \
  --title "$VERSION" \
  --notes-file "$NOTES" \
  --target "$BINARY_SHA"

echo "Published ${VERSION}"
