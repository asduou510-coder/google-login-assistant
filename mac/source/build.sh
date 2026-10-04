#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
flow_app_path="$(cd .. && pwd -P)/Google 登录助手.app"
flow_cache_path="${FLOW_SWIFT_CACHE:-${TMPDIR:-/tmp}/flowlauncher-swift-cache}"
mkdir -p "$flow_app_path/Contents/MacOS" "$flow_cache_path"
cp Info.plist "$flow_app_path/Contents/Info.plist"
swiftc -swift-version 5 -parse-as-library -target arm64-apple-macos13.0 -module-cache-path "$flow_cache_path" FlowLauncher.swift -o "$flow_app_path/Contents/MacOS/FlowLauncher"
"$flow_app_path/Contents/MacOS/FlowLauncher" --self-test
# 应用图标：由 icon.png 生成 AppIcon.icns（iconutil 为苹果官方工具，保证格式有效）
if [ -f icon.png ]; then
  rm -rf "$flow_cache_path/AppIcon.iconset"
  mkdir -p "$flow_cache_path/AppIcon.iconset" "$flow_app_path/Contents/Resources"
  sips -z 1024 1024 icon.png --out "$flow_cache_path/AppIcon.iconset/icon_512x512@2x.png" >/dev/null
  sips -z 512 512  icon.png --out "$flow_cache_path/AppIcon.iconset/icon_512x512.png" >/dev/null
  sips -z 512 512  icon.png --out "$flow_cache_path/AppIcon.iconset/icon_256x256@2x.png" >/dev/null
  sips -z 256 256  icon.png --out "$flow_cache_path/AppIcon.iconset/icon_256x256.png" >/dev/null
  sips -z 256 256  icon.png --out "$flow_cache_path/AppIcon.iconset/icon_128x128@2x.png" >/dev/null
  sips -z 128 128  icon.png --out "$flow_cache_path/AppIcon.iconset/icon_128x128.png" >/dev/null
  sips -z 64 64    icon.png --out "$flow_cache_path/AppIcon.iconset/icon_32x32@2x.png" >/dev/null
  sips -z 32 32    icon.png --out "$flow_cache_path/AppIcon.iconset/icon_32x32.png" >/dev/null
  sips -z 32 32    icon.png --out "$flow_cache_path/AppIcon.iconset/icon_16x16@2x.png" >/dev/null
  sips -z 16 16    icon.png --out "$flow_cache_path/AppIcon.iconset/icon_16x16.png" >/dev/null
  iconutil -c icns "$flow_cache_path/AppIcon.iconset" -o "$flow_app_path/Contents/Resources/AppIcon.icns"
fi
codesign --force --deep --sign - "$flow_app_path"
codesign --verify --deep --strict "$flow_app_path"
