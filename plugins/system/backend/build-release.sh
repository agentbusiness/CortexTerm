#!/usr/bin/env bash
# Source entry point for the standard ccplugin backend build. Never invoked by source review.
# A production Endpoint Security helper additionally needs Apple's approved provisioning and
# Developer ID identities. Missing signing inputs produce an explicitly unusable development
# bundle, not an apparently enabled security service.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release
if [ "$(uname -s)" != Darwin ]; then exit 0; fi

native=src/protection_sensors
out=target/release
bundle="$out/CortexTermEventSensor.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
rm -f "$bundle/Contents/Resources/CortexTermEventSensor.pkg"
xcrun clang -std=c11 -fblocks -O2 -Wall -Wextra -mmacosx-version-min=11.0 \
  -arch arm64 -arch x86_64 "$native/event_sensor.c" -lEndpointSecurity -lbsm \
  -o "$bundle/Contents/MacOS/cortexterm-event-sensor"
cp "$native/Info.plist" "$bundle/Contents/Info.plist"

profile="${CORTEXTERM_ES_PROVISIONING_PROFILE:-}"
identity="${CORTEXTERM_ES_SIGN_IDENTITY:-}"
installer_identity="${CORTEXTERM_ES_INSTALLER_IDENTITY:-}"
notary_profile="${CORTEXTERM_ES_NOTARY_PROFILE:-}"
if [ -z "$profile" ] && [ -z "$identity" ] && [ -z "$installer_identity" ] && [ -z "$notary_profile" ]; then
  rm -f "$bundle/Contents/embedded.provisionprofile" "$bundle/Contents/Resources/CortexTermEventSensor.pkg"
  codesign --force --sign - "$bundle"
  printf '%s\n' 'Endpoint sensor is a development artifact: approved provisioning and Developer ID Application/Installer signing are required before CT offers installation or capture.' >&2
  exit 0
fi
[ -n "$profile" ] && [ -n "$identity" ] && [ -n "$installer_identity" ] && [ -n "$notary_profile" ] || {
  printf '%s\n' 'Production endpoint packaging requires ES_PROVISIONING_PROFILE, ES_SIGN_IDENTITY, ES_INSTALLER_IDENTITY and ES_NOTARY_PROFILE (all prefixed CORTEXTERM_).' >&2
  exit 1
}
[ -f "$profile" ] || { printf '%s\n' 'Endpoint Security provisioning profile not found.' >&2; exit 1; }
stage="$(mktemp -d "${TMPDIR:-/tmp}/ct-event-installer.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
/usr/bin/security cms -D -i "$profile" > "$stage/profile.plist"
team="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$stage/profile.plist")"
case "$team" in
  *[!A-Z0-9]*|'') printf '%s\n' 'Invalid signing team in endpoint provisioning profile.' >&2; exit 1 ;;
esac
[ ${#team} -eq 10 ] || { printf '%s\n' 'Invalid signing team length.' >&2; exit 1; }
app_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$stage/profile.plist")"
[ "$app_id" = "$team.ai.cortexterm.event-sensor" ] || { printf '%s\n' 'Provisioning profile does not match the endpoint helper identifier/team.' >&2; exit 1; }
allowed="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$stage/profile.plist")"
[ "$allowed" = true ] || { printf '%s\n' 'Provisioning profile does not grant Endpoint Security.' >&2; exit 1; }
cp "$native/event-sensor.entitlements.plist" "$stage/entitlements.plist"
/usr/bin/plutil -insert com.apple.application-identifier -string "$app_id" "$stage/entitlements.plist"
/usr/bin/plutil -insert com.apple.developer.team-identifier -string "$team" "$stage/entitlements.plist"
cp "$profile" "$bundle/Contents/embedded.provisionprofile"
codesign --force --options runtime --timestamp --entitlements "$stage/entitlements.plist" --sign "$identity" "$bundle"
codesign --verify --strict "$bundle"
# The caller plugin is signed with the same team so discovery can authenticate the helper and
# installer. This preserves the existing model/plugin wire architecture.
codesign --force --options runtime --timestamp --sign "$identity" "$out/cc-system"

# Build the installer from a clean copy before putting the installer into the packaged bundle.
# The install location is root-owned; CT never sudo-executes a user-writable plugin helper.
destination='Library/Application Support/CortexTerm/Security'
mkdir -p "$stage/root/$destination"
ditto "$bundle" "$stage/root/$destination/CortexTermEventSensor.app"
rm -f "$stage/root/$destination/CortexTermEventSensor.app/Contents/Resources/CortexTermEventSensor.pkg"
# The service that starts the sensor at boot; the postinstall script starts it right away.
mkdir -p "$stage/root/Library/LaunchDaemons"
cp "$native/ai.cortexterm.event-sensor.plist" "$stage/root/Library/LaunchDaemons/"
chmod 644 "$stage/root/Library/LaunchDaemons/ai.cortexterm.event-sensor.plist"
chmod -R go-w "$stage/root"
pkgbuild --root "$stage/root" --scripts "$native/installer-scripts" --ownership recommended --identifier ai.cortexterm.event-sensor.installer \
  --version 1.1.0 --install-location / --sign "$installer_identity" "$stage/CortexTermEventSensor.pkg"
pkgutil --check-signature "$stage/CortexTermEventSensor.pkg"
xcrun notarytool submit "$stage/CortexTermEventSensor.pkg" --keychain-profile "$notary_profile" --wait
xcrun stapler staple "$stage/CortexTermEventSensor.pkg"
xcrun stapler validate "$stage/CortexTermEventSensor.pkg"
cp "$stage/CortexTermEventSensor.pkg" "$bundle/Contents/Resources/CortexTermEventSensor.pkg"
# Adding the installer changes sealed resources; sign the final bundle again.
codesign --force --options runtime --timestamp --entitlements "$stage/entitlements.plist" --sign "$identity" "$bundle"
codesign --verify --strict "$bundle"
