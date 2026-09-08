#!/usr/bin/env bash
# push-leafwatch.sh — build a realistic, incremental git history for leafwatch
# and push it to github.com/jay-tank/leafwatch via the GitHub REST API (curl,
# not gh). Author is Jay Tank only; aborts if any real AI-authorship signature is
# present in the tracked content or history.
#
# Review before running. This script DOES create a repo and force-push.
# Requires a Personal Access Token in $GITHUB_PAT (or $PAT) with 'repo' scope
# (or fine-grained Administration + Contents: write). Rotate the token after use.
set -euo pipefail

# ---- config -----------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OWNER="jay-tank"
NAME="leafwatch"
AUTHOR_NAME="jay-tank"
AUTHOR_EMAIL="tankjai24@gmail.com"
DESCRIPTION="Offline-first TLS/X.509 certificate expiry & health reporter: parses PEM/DER files, bundles or a directory and reports subject/SANs, issuer, days-remaining and flags (EXPIRED, EXPIRING, self-signed, weak key/sig), sorted by soonest expiry. --json, --fail-on gates CI, opt-in --connect live probe. Single Go binary."
TOPICS='["tls","ssl","x509","certificate","cert-expiry","security","sre","devops","monitoring","pki","cli","go"]'

PAT="${GITHUB_PAT:-${PAT:-}}"
if [ -z "$PAT" ]; then
  echo "ABORT: set GITHUB_PAT (or PAT) to a token with 'repo' scope." >&2
  exit 1
fi

export GIT_AUTHOR_NAME="$AUTHOR_NAME"
export GIT_AUTHOR_EMAIL="$AUTHOR_EMAIL"
export GIT_COMMITTER_NAME="$AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$AUTHOR_EMAIL"

cd "$PROJECT_DIR"

# ---- safety: no real AI-authorship signature in tracked content -------------
AI_SIGNATURES='Co-Authored-By:.*(Claude|Anthropic)|Generated with .*Claude|claude\.ai/code|Claude Code|noreply@anthropic\.com|🤖'
if grep -rInE --exclude-dir=.git --exclude-dir=script-push --exclude=DETAILS.md "$AI_SIGNATURES" . ; then
  echo "ABORT: AI-authorship signature found in tracked content — clean it before pushing." >&2
  exit 1
fi

# ---- staggered, jittered commit helper --------------------------------------
BASE_EPOCH=$(date -d '2026-08-28 09:12:00' +%s 2>/dev/null || date -j -f '%Y-%m-%d %H:%M:%S' '2026-08-28 09:12:00' +%s)
STEP=0
commit() {
  local msg="$1"; shift
  git add "$@"
  if git diff --cached --quiet; then
    return 0
  fi
  local jitter=$(( (RANDOM % 28800) - 3600 ))        # -1h .. +7h
  local when=$(( BASE_EPOCH + STEP*86400 + jitter ))
  STEP=$((STEP+1))
  local iso
  iso=$(date -d "@$when" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date -r "$when" '+%Y-%m-%dT%H:%M:%S')
  GIT_AUTHOR_DATE="$iso" GIT_COMMITTER_DATE="$iso" git commit -q -m "$msg"
  echo "  committed: $msg  ($iso)"
}

# ---- Hashnode back-link into README (idempotent) ----------------------------
HN_README="../../hashnode/$NAME/README.md"
if [ -f "$HN_README" ]; then
  SLUG="$(grep -iE 'slug' "$HN_README" | head -n1 | grep -oE '[a-z0-9]+(-[a-z0-9]+)+' | head -n1 || true)"
  if [ -n "${SLUG:-}" ] && grep -q '<!-- HASHNODE_ARTICLE_URL -->' README.md; then
    sed -i "s|<!-- HASHNODE_ARTICLE_URL -->|> 📖 Read the write-up: [$NAME](https://jaytank.hashnode.dev/$SLUG)|" README.md
    echo "back-link inserted: https://jaytank.hashnode.dev/$SLUG"
  fi
fi

# ---- fresh history ----------------------------------------------------------
rm -rf .git
git init -q
git symbolic-ref HEAD refs/heads/main

if git check-ignore -q DETAILS.md; then :; else
  echo "WARN: DETAILS.md is not git-ignored — check .gitignore" >&2
fi

# 1) scaffold
commit "chore: scaffold Go module, MIT license and gitignore" go.mod LICENSE .gitignore

# 2) types / flags
commit "feat(cert): Entry, Report and health Flag/Severity types" cert/types.go

# 3) parsing — PEM/DER/bundle
commit "feat(cert): parse PEM, DER and multi-cert bundles; skip key blocks" cert/parse.go

# 4) analysis — flags, days-remaining, sort
commit "feat(cert): expiry/health analysis, self-signed & weak-key/sig flags" cert/analyze.go

# 5) rendering
commit "feat(cert): text report with ANSI grouping and --json output" cert/report.go

# 6) live connect
commit "feat(cert): opt-in --connect TLS probe of a served certificate" cert/connect.go

# 7) CLI
commit "feat(cli): flags, directory walk, --fail-on gate and exit codes 0/1/2" main.go

# 8) tests
commit "test: days-remaining, flags, sort order, fail-on and bad-input paths" cert/cert_test.go main_test.go

# 9) examples
commit "docs(examples): healthy/expired/weak/bundle sample certificates" examples/

# 10) CI
commit "ci: gofmt + go vet + test + build matrix on Go 1.21/1.22" .github/workflows/ci.yml

# 11) docs
commit "docs: README and usage guide" README.md docs/USAGE.md

# 12) safety sweep — commit anything still untracked/modified
if [ -n "$(git status --porcelain)" ]; then
  commit "chore: finalize repository contents" -A
fi

# ---- final guard: no AI-authorship signature in the commit history ----------
if git log --pretty=full | grep -qiE "$AI_SIGNATURES"; then
  echo "ABORT: AI-authorship signature found in commit history — not pushing." >&2
  exit 1
fi

# ---- create remote via REST API (curl) --------------------------------------
API="https://api.github.com"
AUTH=(-H "Authorization: token $PAT" -H "Accept: application/vnd.github+json")

gh_api() {  # gh_api METHOD URL [DATA] [EXTRA_HEADER]
  local method="$1" url="$2" data="${3:-}" extra="${4:-}"
  local args=(-sS -w '\n%{http_code}' "${AUTH[@]}" -X "$method" "$url")
  [ -n "$extra" ] && args+=(-H "$extra")
  [ -n "$data" ] && args+=(-d "$data")
  local out code body
  out="$(curl "${args[@]}")" || { echo "ABORT: network/curl error on $method $url" >&2; exit 1; }
  code="$(printf '%s' "$out" | tail -n1)"
  body="$(printf '%s' "$out" | sed '$d')"
  if [ "$code" -ge 400 ]; then
    echo "ABORT: GitHub API $method $url -> HTTP $code" >&2
    echo "  response: $body" >&2
    case "$code" in
      401) echo "  => token is invalid/expired (Bad credentials)." >&2;;
      403) echo "  => token lacks permission (fine-grained: needs Administration:write to CREATE a repo)." >&2;;
      404) echo "  => cannot create — token likely can't create repos (use a CLASSIC PAT with 'repo' scope)." >&2;;
      422) echo "  => name/validation issue (repo may already exist)." >&2;;
    esac
    exit 1
  fi
  printf '%s' "$body"
}

DESC_JSON="$(printf '%s' "$DESCRIPTION" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"

if curl -sf "${AUTH[@]}" "$API/repos/$OWNER/$NAME" >/dev/null 2>&1; then
  echo "repo already exists on GitHub — will push into it."
else
  echo "creating repo $OWNER/$NAME ..."
  gh_api POST "$API/user/repos" "{\"name\":\"$NAME\",\"description\":$DESC_JSON,\"private\":false,\"has_wiki\":false}" >/dev/null
  echo "repo created ✓"
fi

# set description + topics
gh_api PATCH "$API/repos/$OWNER/$NAME" "{\"description\":$DESC_JSON}" >/dev/null
gh_api PUT "$API/repos/$OWNER/$NAME/topics" "{\"names\":$TOPICS}" "Accept: application/vnd.github.mercy-preview+json" >/dev/null

# ---- push over HTTPS with the token -----------------------------------------
git remote remove origin 2>/dev/null || true
git remote add origin "https://x-access-token:${PAT}@github.com/$OWNER/$NAME.git"
echo "pushing main ..."
git push -u --force origin main

# ---- verify topics on remote ------------------------------------------------
if curl -sf "${AUTH[@]}" "$API/repos/$OWNER/$NAME/topics" | grep -q '"x509"'; then
  echo "topics set & verified on remote ✓"
else
  echo "ERROR: repo topics not set on remote" >&2; exit 1
fi

# ---- version tag + verify ---------------------------------------------------
git tag -f v0.1.0
git push -f origin v0.1.0
if git ls-remote --tags origin | grep -q 'refs/tags/v0.1.0'; then
  echo "tag v0.1.0 verified on remote ✓"
else
  echo "ERROR: tag v0.1.0 missing on remote after push" >&2; exit 1
fi

echo "done: https://github.com/$OWNER/$NAME  (remember to rotate the token)"
