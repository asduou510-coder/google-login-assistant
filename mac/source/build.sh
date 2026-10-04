#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
flow_app_path="$(cd .. && pwd -P)/Google 登录助手.app"
flow_cache_path="${FLOW_SWIFT_CACHE:-${TMPDIR:-/tmp}/flowlauncher-swift-cache}"
mkdir -p "$flow_app_path/Contents/MacOS" "$flow_cache_path"
cp Info.plist "$flow_app_path/Contents/Info.plist"
swiftc -swift-version 5 -parse-as-library -target arm64-apple-macos13.0 -module-cache-path "$flow_cache_path" FlowLauncher.swift -o "$flow_app_path/Contents/MacOS/FlowLauncher"
"$flow_app_path/Contents/MacOS/FlowLauncher" --self-test
codesign --force --deep --sign - "$flow_app_path"
codesign --verify --deep --strict "$flow_app_path"
