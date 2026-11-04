"""Checks on the GitHub workflow and Dependabot files (run by check.sh).

Static: release.yml runs ci.yml through workflow_call, skips manual runs
off main, and gates the release job on it; ci.yml can be called; Dependabot
and the gitleaks job are configured as documented.

Behaviour: the release job's shell steps run in order, as Actions would
(bash -eo pipefail, $GITHUB_ENV between steps), against throwaway git
repositories with `gh` stubbed. A tag on a commit outside main, or a
version with no CHANGELOG section, must stop the job before any
`gh release create`.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"ok   {msg}")


def die(msg):
    print(f"FAIL {msg}", file=sys.stderr)
    sys.exit(1)


def load(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def triggers(wf):
    # YAML 1.1 reads the bare key `on` as the boolean True.
    return wf.get("on", wf.get(True)) or {}


# ─── Static: release.yml / ci.yml ───────────────────────────────────────────
ci = load(".github/workflows/ci.yml")
rel = load(".github/workflows/release.yml")

"workflow_call" in triggers(ci) or die("ci.yml has no workflow_call trigger")
ok("ci.yml can be called by another workflow")

ci_job = rel["jobs"].get("ci") or die("release.yml has no ci job")
ci_job.get("uses") == "./.github/workflows/ci.yml" or die(f"ci job uses {ci_job.get('uses')!r}")
cond = re.sub(r"\s+", " ", str(ci_job.get("if", ""))).strip()
cond == "github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main'" \
    or die(f"ci job condition is {cond!r}")
ok("release.yml calls ci.yml, and only from main on a manual run")

job = rel["jobs"]["release"]
needs = job.get("needs")
needs = [needs] if isinstance(needs, str) else (needs or [])
"ci" in needs or die("release job does not need ci")
# A skipped or failed `ci` skips `release` unless its `if:` overrides that.
cond = str(job.get("if", ""))
any(f in cond for f in ("always()", "failure()", "cancelled()", "skipped")) \
    and die(f"release job runs despite a skipped/failed ci: if: {cond}")
ok("release job needs ci and has no if: that would run it anyway")

checkout = job["steps"][0]
checkout.get("uses", "").startswith("actions/checkout@") or die("release job does not start with checkout")
checkout.get("with", {}).get("fetch-depth") == 0 or die("release checkout needs fetch-depth: 0 for origin/main")
names = [s.get("name") for s in job["steps"]]
for a, b in (("Commit is on main", "Create release"),
             ("Extract release notes from CHANGELOG.md", "Create release")):
    (a in names and b in names and names.index(a) < names.index(b)) \
        or die(f"step {a!r} must come before {b!r}: {names}")
"merge-base --is-ancestor" in job["steps"][names.index("Commit is on main")]["run"] \
    or die("ancestry step does not use git merge-base --is-ancestor")
ok("release job checks main ancestry and the CHANGELOG before creating a release")


# ─── Static: secrets job, .gitleaks.toml, Dependabot ────────────────────────
sec = ci["jobs"].get("secrets") or die("ci.yml has no secrets job")
sec["steps"][0].get("with", {}).get("fetch-depth") == 0 or die("secrets job must check out full history")
install = next((s for s in sec["steps"] if "GITLEAKS_SUM" in (s.get("env") or {})), None)
install or die("secrets job does not pin the gitleaks module hash")
re.fullmatch(r"v\d+\.\d+\.\d+", install["env"]["GITLEAKS_VERSION"]) or die("gitleaks version not pinned")
re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", install["env"]["GITLEAKS_SUM"]) or die("gitleaks hash malformed")
'"$GITLEAKS_SUM"' in install["run"] or die("gitleaks install step does not compare the hash")
with open(os.path.join(REPO, ".gitleaks.toml"), encoding="utf-8") as fp:
    toml = fp.read()
re.search(r"(?m)^\[extend\]\s*\nuseDefault = true$", toml) or die(".gitleaks.toml does not extend the defaults")
paths = re.findall(r"paths = \['''(.*?)'''\]", toml)
paths == [r"^setup/tests/test_validators\.py$"] or die(f".gitleaks.toml allowlist paths: {paths}")
os.path.isfile(os.path.join(REPO, "setup/tests/test_validators.py")) or die("allowlisted file moved")
ok("gitleaks: pinned + hash-checked, full history, defaults plus one allowlisted file")

dep = {u["package-ecosystem"]: u for u in load(".github/dependabot.yml")["updates"]}
set(dep) == {"github-actions", "pip", "docker"} or die(f"dependabot ecosystems: {sorted(dep)}")
dep["pip"].get("groups") or die("pip updates are not grouped")
sorted(dep["pip"]["directories"]) == ["/", "/darkwatch", "/setup"] or die("pip directories")
sorted(dep["docker"]["directories"]) == ["/darkwatch", "/setup", "/tor"] or die("docker directories")
ign = [i for i in dep["docker"].get("ignore", []) if i.get("dependency-name") == "*"]
(ign and set(ign[0]["update-types"]) >= {"version-update:semver-major", "version-update:semver-minor"}) \
    or die("docker updates are not limited to digests")
ok("dependabot: actions, grouped pip, docker digests only")

audit = load(".github/workflows/deps-audit.yml")
"schedule" in triggers(audit) or die("deps-audit is not scheduled")
reqs = audit["jobs"]["deps-audit"]["strategy"]["matrix"]["requirements"]
want = []
for d, dirs, fs in os.walk(REPO):
    dirs[:] = [x for x in dirs if not x.startswith(".")]
    want += [os.path.relpath(os.path.join(d, f), REPO)
             for f in fs if re.fullmatch(r"requirements.*\.txt", f)]
want.sort()
sorted(reqs) == want or die(f"deps-audit covers {sorted(reqs)}, repo has {want}")
ok("deps-audit: weekly, one leg per requirements file")


# ─── Behaviour: run the release job's steps ─────────────────────────────────
work = tempfile.mkdtemp()


def git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


# origin: main has the real CHANGELOG; `side` has a commit main lacks.
origin = os.path.join(work, "origin")
os.makedirs(origin)
git("init", "-q", "-b", "main", cwd=origin)
shutil.copy(os.path.join(REPO, "CHANGELOG.md"), origin)
git("add", "CHANGELOG.md", cwd=origin)
git("commit", "-qm", "main", cwd=origin)
main_sha = git("rev-parse", "HEAD", cwd=origin)
git("checkout", "-qb", "side", cwd=origin)
git("commit", "-q", "--allow-empty", "-m", "side", cwd=origin)
side_sha = git("rev-parse", "HEAD", cwd=origin)
git("checkout", "-q", "main", cwd=origin)
m = re.search(r"(?m)^## (v\d+\.\d+\.\d+)", open(os.path.join(REPO, "CHANGELOG.md")).read())
m or die("CHANGELOG.md has no released version section")
real_tag = m.group(1)

stubs = os.path.join(work, "bin")
os.makedirs(stubs)
with open(os.path.join(stubs, "gh"), "w") as fp:
    fp.write('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$GH_LOG"\n')
os.chmod(os.path.join(stubs, "gh"), 0o755)


def run_release(case, event, sha, tag):
    """Run the release job's steps for one case; returns (failed step, gh calls)."""
    clone = os.path.join(work, case)
    git("clone", "-q", origin, clone, cwd=work)   # like fetch-depth 0: origin/* present
    git("checkout", "-q", "--detach", sha, cwd=clone)
    gh_log = os.path.join(work, case + ".gh")
    gh_env = os.path.join(work, case + ".env")
    open(gh_log, "w").close()
    open(gh_env, "w").close()
    exprs = {"inputs.tag": tag if event == "workflow_dispatch" else "",
             "github.token": "stub-token"}
    env = {"PATH": f"{stubs}:{os.environ['PATH']}", "HOME": work, "GH_LOG": gh_log,
           "GITHUB_ENV": gh_env, "GITHUB_SHA": sha, "GITHUB_EVENT_NAME": event,
           "GITHUB_REF_NAME": tag if event == "push" else "main"}
    for step in job["steps"]:
        if "run" not in step:
            continue
        for line in open(gh_env).read().splitlines():
            k, _, v = line.partition("=")
            env[k] = v
        step_env = {}
        for k, v in (step.get("env") or {}).items():
            def sub(mt):
                key = mt.group(1).strip()
                key in exprs or die(f"{case}: no stub for ${{{{ {key} }}}}")
                return exprs[key]
            step_env[k] = re.sub(r"\$\{\{(.*?)\}\}", sub, str(v))
        r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                           cwd=clone, env={**env, **step_env}, capture_output=True, text=True)
        if r.returncode != 0:
            return step["name"], open(gh_log).read().splitlines(), r.stderr
    return None, open(gh_log).read().splitlines(), ""


try:
    failed, gh, _ = run_release("dispatch-fake", "workflow_dispatch", main_sha, "v0.0.999")
    failed == "Extract release notes from CHANGELOG.md" or die(f"fake tag on main failed at {failed!r}")
    gh == [] or die(f"fake tag on main called gh: {gh}")
    ok("manual run on main with an unknown version stops at the CHANGELOG step, no release")

    failed, gh, err = run_release("tag-off-main", "push", side_sha, real_tag)
    failed == "Commit is on main" or die(f"tag off main failed at {failed!r}")
    "is not on main" in err or die(f"tag off main: {err!r}")
    gh == [] or die(f"tag off main called gh: {gh}")
    ok("a pushed tag on a commit outside main stops at the ancestry step, no release")

    failed, gh, err = run_release("tag-on-main", "push", main_sha, real_tag)
    failed is None or die(f"tag on main failed at {failed!r}: {err}")
    gh == [f"release create {real_tag} --title DarkWatch {real_tag} --notes-file notes.md --verify-tag"] \
        or die(f"tag on main: gh calls {gh}")
    ok(f"a pushed tag on main ({real_tag}) creates the release")

    failed, gh, err = run_release("dispatch-main", "workflow_dispatch", main_sha, real_tag)
    failed is None or die(f"manual run on main failed at {failed!r}: {err}")
    gh == [f"release create {real_tag} --title DarkWatch {real_tag} --notes-file notes.md --target {main_sha}"] \
        or die(f"manual run on main: gh calls {gh}")
    ok("a manual run on main creates the tag on the checked-out commit")
finally:
    shutil.rmtree(work)

print(f"{passed} checks passed")
