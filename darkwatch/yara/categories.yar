/*
    DarkWatch - Site Category YARA Rules
    Classifies .onion sites by type
*/

rule Marketplace
{
    meta:
        author = "CTI Team"
        description = "Dark web marketplace"
        score = 20

    strings:
        $a = "shop" nocase
        $b = "marketplace" nocase
        $c = "buy now" nocase
        $d = "add to cart" nocase
        $e = "bitcoin" nocase
        $f = "monero" nocase
        $g = "escrow" nocase
        $h = "vendor" nocase

    condition:
        4 of them
}

rule Forum
{
    meta:
        author = "CTI Team"
        description = "Forum or discussion board"
        score = 15

    strings:
        $a = "forum" nocase
        $b = "thread" nocase
        $c = "reply" nocase
        $d = "post" nocase
        $e = "member" nocase
        $f = "register" nocase

    condition:
        4 of them
}

rule Leak_Site
{
    meta:
        author = "CTI Team"
        description = "Data leak or ransomware site"
        score = 40

    strings:
        $a = "leaked" nocase
        $b = "download" nocase
        $c = "breach" nocase
        $d = "dump" nocase
        $e = "victim" nocase
        $f = "published" nocase
        $g = "proof" nocase

    condition:
        4 of them
}

rule Paste_Site
{
    meta:
        author = "CTI Team"
        description = "Paste or text sharing site"
        score = 10

    strings:
        $a = "paste" nocase
        $b = "raw" nocase
        $c = "syntax" nocase
        $d = "expire" nocase
        $e = "anonymous" nocase

    condition:
        3 of them
}

rule Search_Engine
{
    meta:
        author = "CTI Team"
        description = "Dark web search engine"
        score = 5

    strings:
        $a = "search" nocase
        $b = "results" nocase
        $c = "query" nocase
        $d = "index" nocase

    condition:
        3 of them
}

rule Hosting
{
    meta:
        author = "CTI Team"
        description = "Hosting or infrastructure service"
        score = 10

    strings:
        $a = "hosting" nocase
        $b = "domain" nocase
        $c = "onion" nocase
        $d = "server" nocase
        $e = "php" nocase
        $f = "mysql" nocase

    condition:
        3 of them
}
