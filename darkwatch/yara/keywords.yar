/*
    DarkWatch — Generic Threat YARA Rules

    Target-specific keywords (organization names, domains, infrastructure)
    are NOT defined here — they are managed at runtime via the Keywords tab
    in the UI and written to data/user.yar by the YaraScanner generator.

    This file contains only generic threat-intel patterns that apply to
    any operator: credential dumps, ransomware leak sites, IAB listings,
    stealer logs, etc. Keep these stable; they should not need changes
    when targets change.
*/

rule credential_dump
{
    meta:
        author = "CTI Team"
        description = "Credential dump indicators — requires actual dump/leak markers, not just a login/register page"
        score = 40

    strings:
        // Strong leak phrases — unambiguous language of an actual dump
        $leak1  = "combo list"          wide ascii nocase
        $leak2  = "combolist"           wide ascii nocase
        $leak3  = "hash dump"           wide ascii nocase
        $leak4  = "password dump"       wide ascii nocase
        $leak5  = "credential dump"     wide ascii nocase
        $leak6  = "stolen credentials"  wide ascii nocase
        $leak7  = "leaked credentials"  wide ascii nocase
        $leak8  = "leaked passwords"    wide ascii nocase
        $leak9  = "cracked hashes"      wide ascii nocase
        $leak10 = "full leak"           wide ascii nocase
        $leak11 = "database leak"       wide ascii nocase

        // Scale markers — "N million accounts" style claims
        $scale1 = /(\d{2,}[.,]?\d*)\s*(million|billion|thousand)\s*(records?|accounts?|users?|credentials?|passwords?|emails?|rows?)/ nocase
        $scale2 = "pwned" wide ascii nocase

        // Format markers — actual credential lines are the strongest signal
        $fmt_emailpass = /[A-Za-z0-9._%+-]{3,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}:[^\s,"'><]{4,40}/
        $fmt_hashpass  = /[0-9a-f]{32,64}:[^\s,"'><]{4,40}/ nocase

    condition:
        // Fire if EITHER a strong leak phrase is present,
        // OR a scale claim is made,
        // OR the page actually contains at least 3 cred-formatted lines.
        any of ($leak*) or any of ($scale*)
        or #fmt_emailpass >= 3 or #fmt_hashpass >= 3
}

rule ransomware_leak
{
    meta:
        author = "CTI Team"
        description = "Ransomware leak site indicators"
        score = 60

    strings:
        $r1 = "leak" wide ascii nocase
        $r2 = "ransom" wide ascii nocase
        $r3 = "encrypted" wide ascii nocase
        $r4 = "decrypt" wide ascii nocase
        $r5 = "payment" wide ascii nocase
        $r6 = "deadline" wide ascii nocase
        $r7 = "victim" wide ascii nocase
        $r8 = "published" wide ascii nocase
        $r9 = "countdown" wide ascii nocase
        $r10 = "lockbit" wide ascii nocase
        $r11 = "alphv" wide ascii nocase
        $r12 = "blackcat" wide ascii nocase
        $r13 = "clop" wide ascii nocase
        $r14 = "8base" wide ascii nocase

    condition:
        4 of them
}

rule initial_access_broker
{
    meta:
        author = "CTI Team"
        description = "Initial access broker listings"
        score = 60

    strings:
        $i1 = "access for sale" wide ascii nocase
        $i2 = "rdp access" wide ascii nocase
        $i3 = "vpn access" wide ascii nocase
        $i4 = "citrix access" wide ascii nocase
        $i5 = "corporate access" wide ascii nocase
        $i6 = "network access" wide ascii nocase
        $i7 = "initial access" wide ascii nocase
        $i8 = "webshell" wide ascii nocase
        $i9 = "reverse shell" wide ascii nocase
        $i10 = "domain admin" wide ascii nocase

    condition:
        3 of them
}

rule stealer_logs
{
    meta:
        author = "CTI Team"
        description = "Stealer log indicators"
        score = 50

    strings:
        $s1 = "stealer" wide ascii nocase
        $s2 = "redline" wide ascii nocase
        $s3 = "raccoon" wide ascii nocase
        $s4 = "vidar" wide ascii nocase
        $s5 = "aurora" wide ascii nocase
        $s6 = "lumma" wide ascii nocase
        $s7 = "infostealer" wide ascii nocase
        $s8 = "cookies" wide ascii nocase
        $s9 = "autofill" wide ascii nocase
        $s10 = "saved passwords" wide ascii nocase

    condition:
        3 of them
}

rule database_leak
{
    meta:
        author = "CTI Team"
        description = "Database leak indicators"
        score = 40

    strings:
        $d1 = "CREATE TABLE" nocase
        $d2 = "INSERT INTO" nocase
        $d3 = "SELECT * FROM" nocase
        $d4 = "varchar" nocase
        $d5 = "PRIMARY KEY" nocase
        $d6 = "sql dump" nocase
        $d7 = "database dump" nocase
        $d8 = "phpMyAdmin" nocase

    condition:
        4 of them
}

rule email_filter
{
    meta:
        author = "CTI Team"
        description = "Email address patterns"
        score = 10

    strings:
        $email = /\b[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}\b/

    condition:
        $email
}

rule hacking_tools
{
    meta:
        author = "CTI Team"
        description = "Hacking tool references"
        score = 20

    strings:
        $h1 = "exploit" wide ascii nocase
        $h2 = "zero day" wide ascii nocase
        $h3 = "0day" wide ascii nocase
        $h4 = "payload" wide ascii nocase
        $h5 = "shellcode" wide ascii nocase
        $h6 = "reverse shell" wide ascii nocase
        $h7 = "metasploit" wide ascii nocase
        $h8 = "cobalt strike" wide ascii nocase
        $h9 = "mimikatz" wide ascii nocase
        $h10 = "bloodhound" wide ascii nocase

    condition:
        3 of them
}
