#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/native/work"
xcrun swiftc -swift-version 5 -O -parse-as-library "$ROOT"/native/Sources/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds}.swift "$ROOT/native/Release/Appcast.swift" "$ROOT/native/Tests/RulesTests.swift" -o "$ROOT/native/work/rules-tests"
"$ROOT/native/work/rules-tests" "$ROOT/native/work"
