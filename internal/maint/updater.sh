#!/bin/bash
# Trusted installer, embedded in the maintenance runner (`aqmasd maint-run`), which has
# already verified the owner's approval and the release manifest of every configured source
# (GitHub, and a second source where one is configured) and passes them as $METADATA. The
# agreed digests are read from its "github" member, which every record format has. All git,
# dependency and candidate build commands run without root in a new
# PID/user/mount namespace. No candidate script runs on the host.
# Environment (fixed by the runner, never by a request): CACHE BIN STATE TOOLS KNOWN_HOSTS
# REPO DEPLOY_KEY HEALTH_URL METADATA (empty when only recovering an interrupted install).
# REPO is https://… (anonymous fetch of a public repository; DEPLOY_KEY and KNOWN_HOSTS are
# then unused) or ssh://… (read-only DEPLOY_KEY, host keys pinned in KNOWN_HOSTS).
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
cache=$CACHE
bin=$BIN
[[ $EUID == 0 && $cache == /* && $bin == /* && $STATE == /* && $TOOLS == /* ]]
t=$(mktemp -d); chmod 0711 "$t"
out=$(mktemp -d "$cache/.stage.XXXXXXXX")
installstage=$(mktemp -d "$(dirname "$bin")/.aqmasd.XXXXXXXX")
rollback=0
journal=$STATE/pending-rollback.json
status() { echo "$1" > "$out/status"; chmod 0644 "$out/status"; mv -T "$out/status" "$cache/status"; }
cleanup() {
  rc=$?; trap - EXIT; set +e
  if (( rollback )); then
    if restore; then
      status 'Update failed; restored previous binary and verified health.'
    else status 'URGENT: automatic rollback failed; inspect aqmasd and its database.'; fi
  elif (( rc )); then status 'Update refused or build failed; see the aqmas-maint.service journal.'; fi
  rm -rf -- "$t" "$out" "$installstage"; exit "$rc"
}
health() { for _ in {1..20}; do pid=$(systemctl show -p MainPID --value aqmasd); [[ $pid != 0 && /proc/$pid/exe -ef $bin ]] && systemctl is-active -q aqmasd && [[ $(curl --noproxy '*' -fsS --max-time 1 "$HEALTH_URL") == ok ]] && return 0; sleep 1; done; return 1; }
restore() {
  [[ $(sha256sum "$bin.prev" | cut -d' ' -f1) == "$(jq -er '.github["aqmasd-linux-arm64"]' "$journal")" ]] || return 1
  if ! [[ $bin -ef $bin.prev ]]; then ln "$bin.prev" "$installstage/rollback" && mv -T "$installstage/rollback" "$bin" || return 1; fi
  systemctl restart aqmasd && health && install -m0644 "$journal" "$out/restored.json" && mv -T "$out/restored.json" "$cache/latest.json" && sync -f "$cache" && sync -f "$bin" && rm -- "$journal" && sync -f "$STATE"
}
trap cleanup EXIT
if [[ -e $journal ]]; then rollback=1; exit 0; fi
[[ -n $METADATA ]]
case $REPO in
  ssh://*) [[ $DEPLOY_KEY == /* ]]; proto=ssh ;;
  https://*) proto=https ;;
  *) exit 1 ;;
esac
install -m 0600 "$METADATA" "$out/metadata"
v=$(jq -er .version "$out/metadata"); sha=$(jq -er .commit "$out/metadata")
old=$(jq -er '.github["aqmasd-linux-arm64"]' "$cache/latest.json")
pid=$(systemctl show -p MainPID --value aqmasd)
[[ $pid != 0 && /proc/$pid/exe -ef $bin && $(sha256sum "$bin"|cut -d' ' -f1) == "$old" ]]
status "Building approved $v ($sha)."
install -d -o aqmas-build -g aqmas-build -m 0700 "$t/work"
uid=$(id -u aqmas-build); gid=$(id -g aqmas-build)
echo "aqmas-build:x:$uid:$gid:Builder:/tmp/home:/bin/sh" > "$t/passwd"
echo "aqmas-build:x:$gid:" > "$t/group"
chmod 0444 "$t/passwd" "$t/group"

# Whitelist mounts, not a writable checkout on the host root. The builder account
# is dedicated to this unit. No home, system bus, broker state, sockets or spool.
box=(setpriv --reuid=aqmas-build --regid=aqmas-build --clear-groups --no-new-privs
  bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv
  --ro-bind /usr /usr --tmpfs /usr/local --symlink usr/bin /bin --symlink usr/lib /lib
  --ro-bind-try /lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --dir /etc
  --ro-bind "$t/passwd" /etc/passwd --ro-bind "$t/group" /etc/group
  --ro-bind "$TOOLS" /tools --bind "$t/work" /work --chdir /work
  --setenv PATH /tools/go/bin:/tools/bin:/usr/bin:/bin --setenv HOME /tmp/home
  --setenv GOTOOLCHAIN local --setenv GOFLAGS -mod=readonly --setenv GOWORK off
  --setenv CGO_ENABLED 0 --setenv GOMODCACHE /work/modcache --setenv GIT_CONFIG_NOSYSTEM 1
  --setenv BUN_INSTALL_CACHE_DIR /work/buncache)
net=(--share-net --ro-bind /etc/resolv.conf /etc/resolv.conf --ro-bind /etc/ssl /etc/ssl
  --ro-bind-try /etc/pki /etc/pki)
# Exactly one git transport. SSH: the read-only key and the pinned host keys, nothing else.
# HTTPS: anonymous, no credential helper or prompt, no redirects; the system CAs apply.
fetch=(--setenv GIT_ALLOW_PROTOCOL "$proto" --setenv GIT_TERMINAL_PROMPT 0)
if [[ $proto == ssh ]]; then
  install -o aqmas-build -g aqmas-build -m 0400 "$DEPLOY_KEY" "$t/fetch-key"
  install -o aqmas-build -g aqmas-build -m 0400 "$KNOWN_HOSTS" "$t/known_hosts"
  fetch+=(--ro-bind "$t/fetch-key" /key --ro-bind "$t/known_hosts" /known_hosts
    --setenv GIT_SSH_COMMAND 'ssh -F /dev/null -oBatchMode=yes -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes -oUserKnownHostsFile=/known_hosts -i /key')
fi
"${box[@]}" "${net[@]}" "${fetch[@]}" \
  /bin/sh -ec 'git init -q src; cd src; git -c fetch.fsckObjects=true -c credential.helper= -c http.followRedirects=false fetch -q --no-tags -- "$1" refs/heads/main:refs/remotes/source/main "+refs/tags/v*:refs/tags/v*"; test "$(git rev-parse "refs/tags/v$2^{commit}")" = "$3"; test "$(git show refs/remotes/source/main:VERSION)" = "$2"; test "$(git tag --list | grep -Ex "v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" | sort -V | tail -1)" = "v$2"; git merge-base --is-ancestor "$4" "$3"; git merge-base --is-ancestor "$3" refs/remotes/source/main' sh "$REPO" "$v" "$sha" "$(jq -er .commit "$cache/latest.json")"
rm -f "$t/fetch-key" "$t/known_hosts"
status "Fetched $v. Downloading dependencies, then testing and building offline."
"${box[@]}" /bin/sh -ec 'cd src; git -c core.hooksPath=/dev/null checkout -q --detach "$1"; test "$(cat VERSION)" = "$2"' sh "$sha" "$v"
"${box[@]}" "${net[@]}" --setenv GOPROXY https://proxy.golang.org --setenv GOSUMDB sum.golang.org \
  /bin/sh -ec 'cd src; go mod download; go mod verify; git diff --exit-code -- go.mod go.sum
    # The release build installs web dependencies offline: fetch them now, integrity-checked
    # against the frozen lockfile, without running any package script.
    cd web; bun install --frozen-lockfile --ignore-scripts; git diff --exit-code -- bun.lock package.json'
"${box[@]}" --setenv GOPROXY off /bin/sh -ec 'cd src; go test ./...; make release'

# Do not follow paths in a builder-owned directory as root. Copy only the known
# filenames out via the offline sandbox, then hash the root-owned copies.
# SHA256SUMS lists exactly these four; a later build (macOS x86-64) is in SHA256SUMS.extra,
# whose digests the metadata carries under "extra" when the release has that file.
sums=(aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64 aqmasd-linux-arm64)
extra=()
if jq -e 'has("extra")' "$out/metadata" >/dev/null; then extra=(aqmas-darwin-amd64); fi
status "Built $v. Checking all $(( ${#sums[@]} + ${#extra[@]} )) binaries against the approved digests."
mkdir "$out/assets"
for a in "${sums[@]}" ${extra[@]+"${extra[@]}"}; do
  key=github; [[ $a == aqmas-darwin-amd64 ]] && key=extra
  "${box[@]}" /usr/bin/timeout 30 /usr/bin/head -c 134217729 "/work/src/dist/$a" > "$out/assets/$a"
  [[ $(wc -c < "$out/assets/$a") -le 134217728 ]]
  [[ $(sha256sum "$out/assets/$a"|cut -d' ' -f1) == "$(jq -er --arg k "$key" --arg a "$a" '.[$k][$a]' "$out/metadata")" ]]
done
(cd "$out/assets" && sha256sum "${sums[@]}" > SHA256SUMS)
if (( ${#extra[@]} )); then (cd "$out/assets" && sha256sum "${extra[@]}" > SHA256SUMS.extra); fi
install -m 0755 "$out/assets/aqmasd-linux-arm64" "$installstage/new"; rm "$out/assets/aqmasd-linux-arm64"
chmod 0755 "$out/assets"; chmod 0644 "$out/assets/"* "$out/metadata"
# After an earlier automatic rollback the running binary and .prev are one file already
# (and mv refuses to rename a file onto its own hard link).
if ! [[ $bin -ef $bin.prev ]]; then ln "$bin" "$installstage/prev"; mv -T "$installstage/prev" "$bin.prev"; fi
sync -f "$installstage/new"
cp "$cache/latest.json" "$journal.tmp"; mv -T "$journal.tmp" "$journal"; sync -f "$journal"
rollback=1; mv -T "$installstage/new" "$bin"
systemctl restart aqmasd && health || exit 1
if [[ -d $cache/$v ]]; then diff -qr "$out/assets" "$cache/$v"; else mv -T "$out/assets" "$cache/$v"; fi
mv -T "$out/metadata" "$cache/latest.json"; sync -f "$bin"; sync -f "$cache"; rm -- "$journal"; rollback=0; sync -f "$STATE"
status "Installed and health-checked $v ($sha)."
