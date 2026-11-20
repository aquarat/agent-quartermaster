#!/bin/bash
# Trusted installer. All git, dependency and candidate build commands run without
# root in a new PID/user/mount namespace. No candidate script runs on the host.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
cache=/var/lib/aqmas-releases
bin=/usr/local/bin/aqmasd
[[ $EUID == 0 && $REPO == ssh://* && $DEPLOY_KEY == /* ]]
t=$(mktemp -d); chmod 0711 "$t"
out=$(mktemp -d "$cache/.stage.XXXXXXXX")
installstage=$(mktemp -d /usr/local/bin/.aqmasd.XXXXXXXX)
rollback=0
journal=/var/lib/aqmas-updater/pending-rollback.json
status() { echo "$1" > "$out/status"; chmod 0644 "$out/status"; mv -T "$out/status" "$cache/status"; }
cleanup() {
  rc=$?; trap - EXIT; set +e
  if (( rollback )); then
    if restore; then
      status 'Update failed; restored previous binary and verified health.'
    else status 'URGENT: automatic rollback failed; inspect aqmasd and its database.'; fi
  elif (( rc )); then status 'Update refused or build failed; see aqmas-updater.service journal.'; fi
  rm -rf -- "$t" "$out" "$installstage"; exit "$rc"
}
health() { for _ in {1..20}; do pid=$(systemctl show -p MainPID --value aqmasd); [[ $pid != 0 && /proc/$pid/exe -ef $bin ]] && systemctl is-active -q aqmasd && [[ $(curl --noproxy '*' -fsS --max-time 1 "${HEALTH_URL:-http://127.0.0.1:8080/healthz}") == ok ]] && return 0; sleep 1; done; return 1; }
restore() {
  [[ $(sha256sum "$bin.prev" | cut -d' ' -f1) == "$(jq -er '.forgejo["aqmasd-linux-arm64"]' "$journal")" ]] || return 1
  if ! [[ $bin -ef $bin.prev ]]; then ln "$bin.prev" "$installstage/rollback" && mv -T "$installstage/rollback" "$bin" || return 1; fi
  systemctl restart aqmasd && health && install -m0644 "$journal" "$out/restored.json" && mv -T "$out/restored.json" "$cache/latest.json" && sync -f "$cache" && sync -f "$bin" && rm -- "$journal" && sync -f /var/lib/aqmas-updater
}
trap cleanup EXIT
if [[ -e $journal ]]; then rollback=1; exit 0; fi
/usr/local/libexec/aqmas-update-verify > "$out/metadata"
v=$(jq -er .version "$out/metadata"); sha=$(jq -er .commit "$out/metadata")
old=$(jq -er '.forgejo["aqmasd-linux-arm64"]' "$cache/latest.json")
pid=$(systemctl show -p MainPID --value aqmasd)
[[ $pid != 0 && /proc/$pid/exe -ef $bin && $(sha256sum "$bin"|cut -d' ' -f1) == "$old" ]]
status "Building approved $v ($sha)."
install -d -o aqmas-build -g aqmas-build -m 0700 "$t/work"
install -o aqmas-build -g aqmas-build -m 0400 "$DEPLOY_KEY" "$t/fetch-key"
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
  --ro-bind /opt/aqmas-tools /tools --bind "$t/work" /work --chdir /work
  --setenv PATH /tools/go/bin:/tools/bin:/usr/bin:/bin --setenv HOME /tmp/home
  --setenv GOTOOLCHAIN local --setenv GOFLAGS -mod=readonly --setenv GOWORK off
  --setenv CGO_ENABLED 0 --setenv GOMODCACHE /work/modcache --setenv GIT_CONFIG_NOSYSTEM 1)
net=(--share-net --ro-bind /etc/resolv.conf /etc/resolv.conf --ro-bind /etc/ssl /etc/ssl
  --ro-bind-try /etc/pki /etc/pki)
"${box[@]}" "${net[@]}" --ro-bind "$t/fetch-key" /key --ro-bind /etc/ssh/ssh_known_hosts /known_hosts \
  --setenv GIT_ALLOW_PROTOCOL ssh --setenv GIT_SSH_COMMAND 'ssh -F /dev/null -oBatchMode=yes -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes -oUserKnownHostsFile=/known_hosts -i /key' \
  /bin/sh -ec 'git init -q src; cd src; git -c fetch.fsckObjects=true fetch -q --no-tags -- "$1" refs/heads/main:refs/remotes/source/main "+refs/tags/v*:refs/tags/v*"; test "$(git rev-parse "refs/tags/v$2^{commit}")" = "$3"; test "$(git show refs/remotes/source/main:VERSION)" = "$2"; test "$(git tag --list | grep -Ex "v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" | sort -V | tail -1)" = "v$2"; git merge-base --is-ancestor "$4" "$3"; git merge-base --is-ancestor "$3" refs/remotes/source/main' sh "$REPO" "$v" "$sha" "$(jq -er .commit "$cache/latest.json")"
rm "$t/fetch-key"
"${box[@]}" /bin/sh -ec 'cd src; git -c core.hooksPath=/dev/null checkout -q --detach "$1"; test "$(cat VERSION)" = "$2"' sh "$sha" "$v"
"${box[@]}" "${net[@]}" --setenv GOPROXY https://proxy.golang.org --setenv GOSUMDB sum.golang.org \
  /bin/sh -ec 'cd src; go mod download; go mod verify; git diff --exit-code -- go.mod go.sum'
"${box[@]}" --setenv GOPROXY off /bin/sh -ec 'cd src; go test ./...; make release'

# Do not follow paths in a builder-owned directory as root. Copy only the known
# filenames out via the offline sandbox, then hash the root-owned copies.
mkdir "$out/assets"
for a in aqmasd-linux-arm64 aqmas-linux-arm64 aqmas-linux-amd64 aqmas-darwin-arm64; do
  "${box[@]}" /usr/bin/timeout 30 /usr/bin/head -c 134217729 "/work/src/dist/$a" > "$out/assets/$a"
  [[ $(wc -c < "$out/assets/$a") -le 134217728 ]]
  [[ $(sha256sum "$out/assets/$a"|cut -d' ' -f1) == "$(jq -er --arg a "$a" '.forgejo[$a]' "$out/metadata")" ]]
done
(cd "$out/assets" && sha256sum aqmas-* aqmasd-linux-arm64 > SHA256SUMS)
install -m 0755 "$out/assets/aqmasd-linux-arm64" "$installstage/new"; rm "$out/assets/aqmasd-linux-arm64"
chmod 0755 "$out/assets"; chmod 0644 "$out/assets/"* "$out/metadata"
ln "$bin" "$installstage/prev"; mv -T "$installstage/prev" "$bin.prev"
sync -f "$installstage/new"
cp "$cache/latest.json" "$journal.tmp"; mv -T "$journal.tmp" "$journal"; sync -f "$journal"
rollback=1; mv -T "$installstage/new" "$bin"
systemctl restart aqmasd && health || exit 1
if [[ -d $cache/$v ]]; then diff -qr "$out/assets" "$cache/$v"; else mv -T "$out/assets" "$cache/$v"; fi
mv -T "$out/metadata" "$cache/latest.json"; sync -f "$bin"; sync -f "$cache"; rm -- "$journal"; rollback=0; sync -f /var/lib/aqmas-updater
status "Installed and health-checked $v ($sha)."
