#!/usr/bin/env bash
# Checks on .github/ (see check.py): release.yml runs CI first, skips manual
# runs off main, and stops before `gh release create` on a tag outside main
# or a version with no CHANGELOG section; the gitleaks job, .gitleaks.toml,
# Dependabot and the weekly pip-audit are set up as documented.
# Needs: python3 with PyYAML, git.
#   bash tests/workflows/check.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON:-python3}" "$here/check.py"
