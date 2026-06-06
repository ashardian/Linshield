/*
 * LinShield built-in YARA rules.
 *
 * Design goals (v1.0.1):
 *   - PRECISION over recall. Every text/script rule keys on a *contiguous*
 *     construct (one regex), never on far-apart short strings, so a binary
 *     that merely happens to contain the bytes "curl" and "|sh" somewhere is
 *     not flagged.
 *   - Binaries and archives are excluded from script-oriented rules via the
 *     private LooksBinary rule, eliminating false positives on .exe / .apk /
 *     .zip / ELF executables.
 *   - Each rule declares a `verdict` (infected | suspicious). Ambiguous
 *     idioms such as "curl ... | bash" — which are equally common in
 *     legitimate install docs — are reported as SUSPICIOUS hints, not
 *     INFECTED convictions.
 *
 * For real malware coverage, pair these with ClamAV (freshclam) and curated
 * rule feeds dropped into the user YARA directory.
 */

// Files that should never be evaluated by shell/script text rules.
private rule LooksBinary
{
    condition:
        uint32be(0) == 0x7f454c46          // ELF
        or uint16(0)   == 0x5a4d           // MZ   — PE (.exe/.dll)
        or uint16(0)   == 0x4b50           // PK   — zip/apk/jar/docx/xlsx
        or uint32be(0) == 0xcafebabe       // Mach-O fat / Java class
        or uint32be(0) == 0xfeedface       // Mach-O 32-bit
        or uint32be(0) == 0xfeedfacf       // Mach-O 64-bit
        or uint32be(0) == 0x1f8b0800       // gzip
        or uint32be(0) == 0x425a6839       // bzip2 (BZh9)
        or uint32be(0) == 0x28b52ffd       // zstd
        or uint32be(0) == 0xfd377a58       // xz
        or filesize > 3MB
}

// Identifies LinShield's own source and rule files, which necessarily contain
// malware indicators as data/code and would otherwise self-match. Every rule
// below requires `not LinShieldOwnFile`. The sentinel is unique enough that no
// real sample will carry it; LinShield embeds it in its own pattern-bearing
// files (heuristics.py, scanner.py, signatures.py, updater.py, this file).
private rule LinShieldOwnFile
{
    strings:
        $marker = "LS-SELF-EXCLUDE-7f3a9c2e1b" ascii wide
    condition:
        $marker
}
// LS-SELF-EXCLUDE-7f3a9c2e1b  (this rule file is itself LinShield-owned)

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless)"
        severity = "low"
        verdict  = "infected"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        not LinShieldOwnFile and $eicar
}

rule Shell_Downloader_Pipe
{
    meta:
        description = "Shell script that pipes a freshly downloaded payload straight into an interpreter"
        severity = "high"
        verdict  = "suspicious"   // legit installers use this idiom too
    strings:
        $shebang = /#![ \t]*\/(usr\/)?bin\/((env[ \t]+)?(ba|da|k|z)?sh)\b/
        // download tool, then on the SAME command (no newline) pipe into a shell
        $pipe = /(curl|wget)\b[^\n|`]{0,200}\|[ \t]*(sudo[ \t]+)?(ba|da|k|z)?sh\b/ nocase
    condition:
        not LinShieldOwnFile and not LooksBinary and filesize < 1MB and $shebang and $pipe
}

rule Persistence_Cron_Downloader
{
    meta:
        description = "Crontab entry that fetches and executes remote code"
        severity = "high"
        verdict  = "suspicious"
    strings:
        // 5 cron time fields, optional user, then a network fetch piped to a shell — all on one line
        $cron = /(^|\n)[ \t]*([\*\d\/,\-]+[ \t]+){5}([a-z_][a-z0-9_-]*[ \t]+)?[^\n]{0,160}(curl|wget|fetch)\b[^\n]{0,160}\|[ \t]*(ba)?sh\b/ nocase
    condition:
        not LinShieldOwnFile and not LooksBinary and filesize < 1MB and $cron
}

rule Obfuscated_Decode_Exec
{
    meta:
        description = "Decoded/obfuscated payload passed directly to an interpreter"
        severity = "high"
        verdict  = "suspicious"
    strings:
        $sh = /(base64[ \t]+(--decode|-d)|openssl[ \t]+enc[ \t]+-d)[^\n]{0,120}\|[ \t]*(ba)?sh\b/ nocase
        $py = /(eval|exec)[ \t]*\([ \t]*(base64\.b64decode|codecs\.decode|zlib\.decompress|__import__[ \t]*\([ \t]*['"]base64)/ nocase
        $js = /eval[ \t]*\([ \t]*(atob|Buffer\.from)[ \t]*\(/ nocase
        $ps = /FromBase64String[^\n]{0,80}(IEX|Invoke-Expression)/ nocase
    condition:
        not LinShieldOwnFile and not LooksBinary and filesize < 2MB and any of them
}

rule Reverse_Shell_OneLiner
{
    meta:
        description = "Interactive reverse-shell construct"
        severity = "critical"
        verdict  = "infected"
    strings:
        $devtcp = /\/dev\/tcp\/[0-9A-Za-z.\-]+\/\d{1,5}/                       // bash /dev/tcp/host/port
        $sh_i   = /(ba)?sh[ \t]+-i[ \t]*(>|2?>&|&)[^\n]{0,40}\/dev\/tcp\// nocase   // sh -i >& /dev/tcp/..
        $nc_e   = /\b(nc|ncat|netcat)\b[^\n]{0,40}[ \t]-e[ \t]+\/?(bin\/)?(ba)?sh\b/ nocase
        $py_pty = /import[ \t]+pty[^\n]{0,120}pty\.spawn[ \t]*\(/ nocase
        $py_dup = /dup2[ \t]*\([ \t]*s\.fileno[ \t]*\(\)/ nocase
        $perl   = /socket[ \t]*\([ \t]*\w+[ \t]*,[ \t]*PF_INET/ nocase
    condition:
        not LinShieldOwnFile and any of them
}

rule Cryptominer_Indicators
{
    meta:
        description = "Strings characteristic of crypto-mining malware"
        severity = "high"
        verdict  = "infected"
    strings:
        $stratum  = "stratum+tcp://" nocase
        $stratums = "stratum+ssl://" nocase
        $xmrig    = "xmrig" nocase
        $minerd   = "minerd" nocase
        $donate   = "donate-level" nocase
        $algo     = "randomx" nocase
        $nicehash = "nicehash" nocase
        $cpuminer = "cpuminer" nocase
    condition:
        not LinShieldOwnFile and 2 of them
}
