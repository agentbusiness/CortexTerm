# Electron branded as CortexTerm for macOS, shared by scripts/build-app.sh and the release scripts.
# Source it, then: electron_mac_branded <electron npm package> <destination package folder> <icns>
#
# The destination is a package folder like node_modules/electron: dist/CortexTerm.app (renamed,
# its executable, name and icon CortexTerm, so the Dock, Force Quit and Activity Monitor show
# CortexTerm; ad-hoc signed), path.txt (the executable inside dist/) and version. Its fuses: cookie
# encryption on (the agent browser's cookies are encrypted with a key Electron keeps in the
# Keychain, "CortexTerm Safe Storage"); `fuses` records it. Needs $repo/ui/node_modules/@electron/fuses.

# This branding's number in the release catalog, which names an Electron "<version>-<number>". An
# installed updater keeps one folder per name and never replaces it, and a release reuses the archive
# of a name already published, so raise this whenever what electron_mac_branded makes changes.
# 2: the first archives published kept "Electron Helper".
ELECTRON_BRANDING=2

electron_mac_branded() {
  local src="$1" dst="$2" icns="$3"
  rm -rf "$dst"
  mkdir -p "$dst/dist"
  local source_app
  source_app="$(ls -d "$src"/dist/*.app | head -1)"
  ditto "$source_app" "$dst/dist/CortexTerm.app"
  local macos="$dst/dist/CortexTerm.app/Contents/MacOS"
  [ -f "$macos/Electron" ] && mv "$macos/Electron" "$macos/CortexTerm"
  # The helpers too, so Activity Monitor shows "CortexTerm Helper (Renderer)", not "Electron Helper":
  # Electron looks for "Electron Helper.app" first, then "<CFBundleName> Helper.app".
  local frameworks="$dst/dist/CortexTerm.app/Contents/Frameworks" helper base name
  for helper in "$frameworks"/Electron\ Helper*.app; do
    [ -d "$helper" ] || continue
    base="${helper##*/}"
    base="${base%.app}"
    name="CortexTerm${base#Electron}"
    mv "$helper/Contents/MacOS/$base" "$helper/Contents/MacOS/$name"
    /usr/libexec/PlistBuddy -c "Set :CFBundleName $name" "$helper/Contents/Info.plist"
    mv "$helper" "$frameworks/$name.app"
  done
  local plist="$dst/dist/CortexTerm.app/Contents/Info.plist" key
  for key in CFBundleName CFBundleDisplayName CFBundleExecutable; do
    /usr/libexec/PlistBuddy -c "Set :$key CortexTerm" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Add :$key string CortexTerm" "$plist"
  done
  cp "$icns" "$dst/dist/CortexTerm.app/Contents/Resources/CortexTerm.icns"
  /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile CortexTerm.icns" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string CortexTerm.icns" "$plist"
  # Fuses are bits in the executable: flipped before it is signed.
  node --input-type=module -e '
const { flipFuses, FuseVersion, FuseV1Options } = await import(process.argv[1]);
await flipFuses(process.argv[2], { version: FuseVersion.V1, [FuseV1Options.EnableCookieEncryption]: true });
' "$repo/ui/node_modules/@electron/fuses/dist/index.js" "$dst/dist/CortexTerm.app" || return 1
  printf 'cookie-encryption' > "$dst/fuses"
  codesign --force --deep --sign - "$dst/dist/CortexTerm.app" >/dev/null 2>&1
  printf '%s' "CortexTerm.app/Contents/MacOS/CortexTerm" > "$dst/path.txt"
  /usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"], end="")' "$src/package.json" > "$dst/version"
}
