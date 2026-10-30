// CortexTerm's own rules for the macOS stealers of 2024 to 2026, written for this project from the
// public reports on each family (no rule text copied). The sweep runs them next to Apple's
// XProtect rules. `severity` is what a hit is reported as.

rule CortexTerm_AMOS_PasswordPrompt
{
    meta:
        description = "AppleScript that asks for the login password in a hidden-answer dialog and checks it with dscl (AMOS, Odyssey and their copies)"
        family = "AMOS"
        severity = "high"
    strings:
        $hidden = "hidden answer" nocase
        $dialog = "display dialog" nocase
        $authonly = "-authonly"
        $dscl = "dscl"
    condition:
        filesize < 20MB and $hidden and $dialog and $authonly and $dscl
}

rule CortexTerm_Stealer_BrowserAndWallets
{
    meta:
        description = "A program or script that names several browser password and cookie stores together with crypto wallets"
        family = "generic stealer"
        severity = "high"
    strings:
        $b1 = "Login Data"
        $b2 = "Cookies.binarycookies"
        $b3 = "key4.db"
        $b4 = "logins.json"
        $b5 = "Local State"
        $b6 = "login.keychain-db"
        $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
        $w3 = "Exodus/exodus.wallet"
        $w4 = "Electrum/wallets"
        $w5 = "atomic/Local Storage"
        $w6 = "Ledger Live"
        $w7 = "Telegram Desktop/tdata"
    condition:
        filesize < 30MB and 3 of ($b*) and 2 of ($w*)
}

rule CortexTerm_Banshee_PasswordMarker
{
    meta:
        description = "Banshee stealer: writes the captured login password to a password-entered file"
        family = "Banshee"
        severity = "high"
    strings:
        $marker = "password-entered"
        $dscl = "dscl"
        $keychain = "Keychains"
    condition:
        filesize < 30MB and $marker and ($dscl or $keychain)
}

rule CortexTerm_Cthulhu_Keychain
{
    meta:
        description = "Cthulhu stealer (Go): the keychain copy routine named in its binary"
        family = "Cthulhu"
        severity = "high"
    strings:
        $fn = "copyKeychainFile"
        $kc = "login.keychain"
    condition:
        filesize < 50MB and $fn and $kc
}

rule CortexTerm_ShaiHulud_Payload
{
    meta:
        description = "Shai-Hulud npm worm: its loader, payload and stolen-secret file names"
        family = "Shai-Hulud"
        severity = "high"
    strings:
        $a = "setup_bun.js"
        $b = "bun_environment.js"
        $c = "truffleSecrets.json"
        $d = "actionsSecrets.json"
        $e = "SHA1HULUD"
        $f = "Sha1-Hulud" nocase
        $g = "shai-hulud-workflow.yml"
    condition:
        filesize < 20MB and 2 of them
}

rule CortexTerm_Nx_s1ngularity
{
    meta:
        description = "Nx s1ngularity: a script that has AI coding CLIs search the disk for secrets into /tmp/inventory.txt"
        family = "Nx s1ngularity"
        severity = "high"
    strings:
        $inv = "/tmp/inventory.txt"
        $y1 = "--dangerously-skip-permissions"
        $y2 = "--yolo"
        $y3 = "--trust-all-tools"
    condition:
        filesize < 5MB and $inv and any of ($y*)
}

rule CortexTerm_ClickFix_Dropper
{
    meta:
        description = "A small script that downloads a program, strips its quarantine flag and runs it (the ClickFix pattern)"
        family = "ClickFix"
        severity = "medium"
    strings:
        $curl = /curl\s+(-[a-zA-Z]+\s+)*https?:\/\//
        $xattr = /xattr\s+(-[a-z]+\s+)*(-c|-d\s+com\.apple\.quarantine)/
        $chmod = "chmod +x"
    condition:
        filesize < 200KB and $curl and $xattr and $chmod
}
