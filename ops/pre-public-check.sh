#!/usr/bin/env bash
# Pre-public release gate for DarkWatch.
#
# Run from repo root before making the GitHub repo public:
#   ./ops/pre-public-check.sh
#
# Exits non-zero on any blocking finding.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
warn() { printf '\033[1;33m[pre-public WARN]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[pre-public OK]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[pre-public FAIL]\033[0m %s\n' "$*" >&2; fail=1; }

hdr() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hdr "Tracked secret-like files"
if git ls-files | grep -E '(^|/)\.env$|\.env\.[^/]+$|\.pem$|\.key$|\.session$|wg_confs/[^/]+\.conf$' | grep -v '^\.env\.example$' | grep -q .; then
    git ls-files | grep -E '(^|/)\.env$|\.env\.[^/]+$|\.pem$|\.key$|\.session$|wg_confs/[^/]+\.conf$' | grep -v '^\.env\.example$' | while read -r f; do
        bad "tracked file must not ship: $f"
    done
else
    ok "no .env / keys / sessions / real wg configs tracked"
fi

hdr "Gitleaks (working tree + full git history)"
if command -v gitleaks >/dev/null 2>&1; then
    if gitleaks detect --source . --no-banner --redact >/tmp/gitleaks-now.txt 2>&1; then
        ok "gitleaks clean (current tree)"
    else
        bad "gitleaks findings in current tree — see /tmp/gitleaks-now.txt"
    fi
    if gitleaks detect --source . --no-banner --redact >/tmp/gitleaks-git.txt 2>&1; then
        ok "gitleaks clean (git history)"
    else
        bad "gitleaks findings in git history — see /tmp/gitleaks-git.txt"
    fi
else
    warn "gitleaks not installed — install with: brew install gitleaks"
fi

hdr "High-risk patterns in tracked files"
if rg -n --hidden --glob '!.git' \
    -e 'ghp_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{20,}' \
    -e 'sk-[A-Za-z0-9]{20,}' \
    -e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
    -e 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' \
    -e 'mongodb(\+srv)?://[^"\s]+' \
    -e 'postgres(ql)?://[^"\s]+' \
    . 2>/dev/null; then
    bad "token/URL/private-key pattern matched above"
else
    ok "no obvious live token patterns in tracked files"
fi

hdr "Git history depth"
commits="$(git rev-list --count HEAD 2>/dev/null || echo 0)"
ok "commit count on HEAD: $commits"
if (( commits > 5 )); then
    warn "history has $commits commits — review full log before going public"
fi

hdr "Manual items before public"
warn "Add branch protection on main: PR required, no force-push, no delete"
warn "Repo delete/recreate wipes Activity + PR history if you need a blank slate"

if (( fail )); then
    echo ""
    bad "blocking issues found — do not make the repo public yet"
    exit 1
fi

echo ""
ok "pre-public checks passed"
