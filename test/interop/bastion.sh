# Sourced by run-setup.sh on the sealed broker with the runner in its test layout
# (docs/BASTION-ACCESS.md §12): access to the bastion itself.
#
#   allow access (runner test layout: real installer, real `sshd -T` on the produced files)
#   → inspect grant used through a real sshd with the produced configuration
#   → root refused until root's allowlist names this host, then a root grant with a bucket
#     open that is closed before the certificate is handed out, used through a real sshd
#     that enforces the allowlist's from= address
#   → a routine task queued by the agent and approved; an update with the kernel excluded
#   → remove access
#
# The machine has no aqmas-inspect account and the test cannot create one: account
# management goes to the hook, and the inspect login is exercised on a second sshd where the
# produced inspect files are applied to the test user.

# sys_tool writes the stand-in for the bastion's system tools (the hook's `sys` verb):
# every call is logged; sshd is the real one, evaluating the produced files.
bastion_sys_tool() {
	cat >"$T/sys" <<EOF
#!/usr/bin/env bash
set -u
tool=\$1; shift
echo "\$tool \$*" >>"$T/sys.log"
case \$tool in
getent) [[ -e $T/inspect-account ]] && echo "aqmas-inspect:x:990:990::/:/bin/sh" || exit 2 ;;
useradd) touch "$T/inspect-account" ;;
userdel) rm -f "$T/inspect-account" ;;
id) echo "aqmas-inspect systemd-journal" ;;
passwd | usermod | loginctl) ;;
rpm) cat "$T/rpm.list" ;;
systemd-run) sed -i 's/^bash\t.*/bash\t5.2.99-1.fc99.aarch64/' "$T/rpm.list" ;;  # "dnf upgrade": one package moves
systemctl) [[ \$1 == show ]] && echo loaded; exit 0 ;;
journalctl) [[ \$1 == --disk-usage ]] && echo "Archived and active journals take up 64.0M in the file system."; exit 0 ;;
df) exec df -P -h / ;;
sshd) # the real sshd on the produced files, with /etc/ssh mapped into the sysroot
  cfg=\$(mktemp "$T/sshd-check.XXXXXX")
  { echo "HostKey $T/sshd/hostkey"; cat "$L"/sysroot/etc/ssh/sshd_config.d/*.conf; } | sed "s|/etc/ssh/|$L/sysroot/etc/ssh/|g" >"\$cfg"
  args=()
  while [[ \$# -gt 0 ]]; do case \$1 in -f) shift ;; *) args+=("\$1") ;; esac; shift; done
  "$SSHD" "\${args[@]}" -f "\$cfg" | sed "s|$L/sysroot/etc/ssh/|/etc/ssh/|g"; rc=\${PIPESTATUS[0]}; rm -f "\$cfg"; exit "\$rc" ;;
*) exit 0 ;;
esac
EOF
	chmod +x "$T/sys"
}

# bastion_sshd PORT NAME [SED]: a throwaway sshd on the files the runner produced, with
# /etc/ssh mapped into the sysroot (and SED applied: the inspect instance maps the inspect
# account onto the test user).
bastion_sshd() {
	local port=$1 name=$2 edit=${3:-} dir="$T/sshd-$2"
	mkdir -p "$dir"
	{
		printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nStrictModes no\nUsePAM no\n' "$port" "$T/sshd/hostkey" "$dir/pid"
		cat "$L"/sysroot/etc/ssh/sshd_config.d/*.conf
	} | sed "s|/etc/ssh/|$L/sysroot/etc/ssh/|g${edit:+;$edit}" >"$dir/sshd_config"
	"$SSHD" -D -e -f "$dir/sshd_config" >"$dir/log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return; sleep 0.1; done
	fail "sshd ($name) did not start: $(cat "$dir/log")"
}

bastion_scenario() {
	local PB PI pid id out CAFP ENR bad
	PB=$(free_port) PI=$(free_port)
	bastion_sys_tool
	: >"$T/sys.log"
	printf 'bash\t5.2.26-3.fc99.aarch64\nkernel-core\t6.11.4-300.fc99.aarch64\nopenssh-server\t9.6p1-1.fc99.aarch64\n' >"$T/rpm.list"
	mkdir -p "$L/sysroot/etc/ssh/sshd_config.d" "$L/sysroot/boot/loader/entries"
	printf '# test sshd_config\nInclude /etc/ssh/sshd_config.d/*.conf\n' >"$L/sysroot/etc/ssh/sshd_config"
	cp "$T/sshd/hostkey.pub" "$L/sysroot/etc/ssh/ssh_host_ed25519_key.pub"
	echo "title Test" >"$L/sysroot/boot/loader/entries/test.conf"
	CAFP=$(ssh-keygen -lf "$T/sshd/ca.pub" | cut -d' ' -f2)

	# --- not installed: nothing to ask for, and only the access task is offered ---
	"$AQMAS" bastion >"$T/bastion-before.out" 2>&1 || true
	grep -q "not installed" "$T/bastion-before.out" || fail "bastion access offered before it is installed: $(cat "$T/bastion-before.out")"
	[[ $(owner setup-state bastion-access) == available && $(owner setup-state bastion-allow) == blocked:* && $(owner setup-state bastion-access-remove) == blocked:* ]] || fail "bastion tasks before install: $(owner setup-state bastion-access) / $(owner setup-state bastion-allow)"

	# --- a CA other than the one root can verify is refused; nothing changes ---
	cp "$L/etc/config.toml" "$T/config.before-bastion"
	bad="SHA256:$(printf 'A%.0s' {1..43})"
	owner setup-run bastion-access "{\"name\":\"bastion\",\"address\":\"127.0.0.1\",\"port\":$PB,\"admin_user\":\"$ME\",\"ssh_ca\":\"$bad\"}"
	owner setup-wait bastion-access failed 30 >/dev/null
	cmp -s "$L/etc/config.toml" "$T/config.before-bastion" && [[ ! -e $L/sysroot/etc/ssh/aqmas_user_ca.pub && ! -e $T/inspect-account ]] || fail "a refused access task left changes behind"

	# --- allow access: the real installer writes the files, the real sshd accepts them ---
	owner setup-run bastion-access "{\"name\":\"bastion\",\"address\":\"127.0.0.1\",\"port\":$PB,\"admin_user\":\"$ME\",\"ssh_ca\":\"$CAFP\"}"
	owner setup-wait bastion-access done 60 >/dev/null
	grep -q '^\[bastion\]' "$L/etc/config.toml" && grep -q "^admin_user *= *\"$ME\"" "$L/etc/config.toml" && grep -q 'comments must survive' "$L/etc/config.toml" || fail "[bastion] not written: $(cat "$L/etc/config.toml")"
	cmp -s <(cut -d' ' -f1-2 "$L/sysroot/etc/ssh/aqmas_user_ca.pub") <(cut -d' ' -f1-2 "$T/sshd/ca.pub") || fail "the installed CA is not the broker's SSH CA"
	[[ $(cat "$L/sysroot/etc/ssh/aqmas_principals/aqmas-inspect") == aqmas-inspect@bastion && ! -e $L/sysroot/etc/ssh/aqmas_principals/$ME ]] || fail "principals files after install"
	grep -q "ForceCommand $AQMASD inspect" "$L/sysroot/etc/ssh/sshd_config.d/90-aqmas-inspect.conf" && grep -q 'DisableForwarding yes' "$L/sysroot/etc/ssh/sshd_config.d/90-aqmas-inspect.conf" || fail "no forced-command block"
	grep -q '^sshd -T .*user=aqmas-inspect' "$T/sys.log" && grep -q '^useradd --system --no-create-home --home-dir / --shell /bin/sh --groups systemd-journal aqmas-inspect$' "$T/sys.log" || fail "account or sshd check not run: $(cat "$T/sys.log")"
	owner login >/dev/null
	[[ $(owner seal-status) == buckets && -z $(owner open-buckets) ]] || fail "the restart after the access task left something open"
	[[ $(owner setup-state bastion-access) == done && $(owner setup-state bastion-allow) == available ]] || fail "queue after install: $(owner setup-state bastion-allow)"
	"$AQMAS" bastion >"$T/bastion.out" 2>&1 || fail "aqmas bastion: $(cat "$T/bastion.out")"
	grep -q 'NOT allowed' "$T/bastion.out" || fail "root offered with an empty allowlist: $(cat "$T/bastion.out")"
	ok "access to the bastion installed by the runner: CA, inspect principals, forced-command block, [bastion] table"

	# --- inspect: an amber card, a certificate that confines itself, used through a real sshd ---
	bastion_sshd "$PI" inspect "s|Match User aqmas-inspect|Match User $ME|;s|aqmas_principals/%u|aqmas_principals/aqmas-inspect|"
	"$AQMAS" cert bastion --why "read the broker's log" </dev/null >"$T/inspect.out" 2>"$T/inspect.err" &
	pid=$!
	id=$(owner wait bastion interop-host 20)
	owner item request "$id" | grep -q '"level":"inspect"' || fail "inspect card: $(owner item request "$id")"
	if owner batch "$id" 2>/dev/null; then fail "a batch decided a bastion request"; fi
	owner approve "$id" 600 >"$T/inspect-decision.json" 2>"$T/inspect-sign.err" || { cat "$T/inspect-sign.err"; fail "approve inspect"; }
	wait $pid || { cat "$T/inspect.err"; fail "aqmas cert bastion"; }
	grep -q '"kind":"bastion"' "$T/inspect-sign.err" && grep -q '"level":"inspect"' "$T/inspect-sign.err" && ! grep -q standing_hours "$T/inspect-sign.err" || fail "inspect canonical: $(cat "$T/inspect-sign.err")"
	local dir="$AQMAS_CACHE_DIR/aqmas-inspect@bastion" key cert
	key=$(ls "$dir"/*.key 2>/dev/null | head -1) || true
	[[ -n $key ]] || key=$(grep -rl 'OPENSSH PRIVATE KEY' "$dir" | head -1)
	cert=$(grep -rl -- '-cert-v01@openssh.com' "$dir" | head -1)
	[[ -n $key && -n $cert ]] || fail "no cached inspect certificate in $dir: $(ls -R "$dir")"
	ssh-keygen -Lf "$cert" >"$T/inspect-cert.txt"
	grep -q 'force-command /usr/local/bin/aqmasd inspect' "$T/inspect-cert.txt" && grep -q 'aqmas-inspect@bastion' "$T/inspect-cert.txt" && grep -q 'Extensions: (none)' "$T/inspect-cert.txt" || fail "inspect certificate: $(cat "$T/inspect-cert.txt")"
	issh() { ssh -F none -T -o IdentitiesOnly=yes -o IdentityAgent=none -i "$key" -o CertificateFile="$cert" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -p "$PI" "$ME@127.0.0.1" "$@"; }
	issh help >"$T/inspect-help.out" 2>&1 || fail "inspect help through sshd: $(cat "$T/inspect-help.out" "$T/sshd-inspect/log")"
	grep -q 'aqmas inspect: read-only view of the bastion' "$T/inspect-help.out" || fail "the forced command did not answer: $(cat "$T/inspect-help.out")"
	# Whatever is asked for, the session is the forced command: no shell, no file.
	if issh 'cat /etc/passwd; id' >"$T/inspect-shell.out" 2>&1; then fail "the inspect account ran a shell command"; fi
	grep -q 'not an inspect command' "$T/inspect-shell.out" && ! grep -q "^root:" "$T/inspect-shell.out" || fail "inspect refusal: $(cat "$T/inspect-shell.out")"
	# A second run within the hour reuses the certificate: no new card.
	"$AQMAS" cert bastion --why "read the log again" </dev/null >"$T/inspect2.out" 2>"$T/inspect2.err" || { cat "$T/inspect2.err"; fail "inspect reuse"; }
	grep -q 'reusing grant' "$T/inspect2.err" || fail "the inspect certificate was not reused: $(cat "$T/inspect2.err")"
	[[ -z $(owner open-buckets) ]] || fail "the inspect approval left a bucket open: $(owner open-buckets)"
	ok "inspect: one tap, certificate with its own forced command, used through a real sshd; no shell behind it"

	# --- root: refused until root's allowlist names this host and address ---
	if "$AQMAS" ssh bastion --level root --why "must be refused" -- true </dev/null >"$T/root-refused.out" 2>&1; then fail "root without the allowlist"; fi
	grep -q 'may not ask for root' "$T/root-refused.out" || fail "root refusal: $(cat "$T/root-refused.out")"
	ENR=$(owner bastion | bun -e 'const v=await Bun.stdin.json();console.log(v.hosts.find(h=>h.name==="interop-host").id)')
	owner setup-run bastion-allow "{\"hosts\":[{\"id\":\"$ENR\",\"name\":\"interop-host\",\"address\":\"127.0.0.1\"}]}"
	owner setup-wait bastion-allow done 30 >/dev/null
	[[ $(cat "$L/sysroot/etc/ssh/aqmas_principals/$ME") == "from=\"127.0.0.1\" $ME@bastion" ]] || fail "admin principals: $(cat "$L/sysroot/etc/ssh/aqmas_principals/$ME" 2>&1)"
	[[ $(owner bastion | bun -e 'const v=await Bun.stdin.json();console.log(v.hosts.filter(h=>h.allowed).map(h=>h.name+"@"+h.allowed_address).join())') == interop-host@127.0.0.1 ]] || fail "allowlist not shown: $(owner bastion)"
	bastion_sshd "$PB" root

	# sshd itself enforces the address: with another address on root's list, a properly
	# approved root certificate is refused at the door.
	cp "$L/sysroot/etc/ssh/aqmas_principals/$ME" "$T/principals.keep"
	echo "from=\"192.0.2.99\" $ME@bastion" >"$L/sysroot/etc/ssh/aqmas_principals/$ME"
	"$AQMAS" ssh bastion --level root --ttl 5m --why "interop: from another address" -- echo root-ok </dev/null >"$T/root-from.out" 2>"$T/root-from.err" &
	pid=$!
	owner approve-root "$(owner wait bastion interop-host 20)" 300 close >/dev/null 2>&1 || fail "approve root (from= case)"
	if wait $pid; then fail "sshd accepted a root certificate from an address that is not on root's list"; fi
	[[ ! -s $T/root-from.out ]] && grep -qi 'permission denied' "$T/root-from.err" || fail "from= refusal: $(cat "$T/root-from.err")"
	cp "$T/principals.keep" "$L/sysroot/etc/ssh/aqmas_principals/$ME"

	# A bucket is open (a standing rule holds the SSH CA): the red card must list it.
	"$AQMAS" ssh testhost --fresh --why "open something first" -- echo granted </dev/null >"$T/ssh.out" 2>"$T/ssh.err" &
	pid=$!
	owner approve "$(owner wait ssh interop-host 20)" 600 1 >/dev/null 2>&1 || fail "approve with a standing rule"
	wait $pid || { cat "$T/ssh.err"; fail "ssh with a standing rule"; }
	[[ -n $(owner open-buckets) ]] || fail "fixture: nothing is open before the root request"

	"$AQMAS" ssh bastion --level root --ttl 10m --why "interop: fix the broker" -- echo root-ok </dev/null >"$T/root.out" 2>"$T/root.err" &
	pid=$!
	id=$(owner wait bastion interop-host 20)
	owner item request "$id" >"$T/root-card.json"
	grep -q '"level":"root"' "$T/root-card.json" && grep -q '"open_buckets":\["SSH user CA"\]' "$T/root-card.json" && grep -q '"risk":"high"' "$T/root-card.json" || fail "red card: $(cat "$T/root-card.json")"
	if owner batch "$id" 2>/dev/null; then fail "a batch decided a root request"; fi
	if owner approve "$id" 600 1 2>/dev/null; then fail "a root session was approved with a standing rule"; fi
	if owner approve "$id" 7200 2>/dev/null; then fail "a root session beyond one hour"; fi
	owner approve-root "$id" 600 close >"$T/root-decision.json" 2>"$T/root-sign.err" || { cat "$T/root-sign.err"; fail "approve root"; }
	grep -q '"open_buckets":"\[\\"SSH user CA\\"\]"' "$T/root-sign.err" && grep -q '"close_buckets":true' "$T/root-sign.err" && grep -q '"level":"root"' "$T/root-sign.err" || fail "root canonical: $(cat "$T/root-sign.err")"
	grep -q '"closed_count":1' "$T/root-decision.json" && grep -q '"alert":"' "$T/root-decision.json" || fail "root decision: $(cat "$T/root-decision.json")"
	[[ -z $(owner open-buckets) ]] || fail "buckets still open after a root approval with close first: $(owner open-buckets)"
	wait $pid || { cat "$T/root.err" "$T/sshd-root/log"; fail "aqmas ssh bastion --level root"; }
	[[ $(cat "$T/root.out") == root-ok ]] && grep -q 'ROOT on the bastion' "$T/root.err" || fail "root session: '$(cat "$T/root.out")' $(cat "$T/root.err")"
	[[ -z $(ls -d "$AQMAS_CACHE_DIR"/.bastion-root-* "$AQMAS_CACHE_DIR/$ME@bastion" 2>/dev/null) ]] || fail "the root certificate was kept: $(ls -a "$AQMAS_CACHE_DIR")"
	owner bastion >"$T/bastion-view.json"
	grep -q '"root_until":"' "$T/bastion-view.json" && grep -q '"level":"root"' "$T/bastion-view.json" && grep -q '"delivered_at":"' "$T/bastion-view.json" || fail "root session not shown: $(cat "$T/bastion-view.json")"
	owner state | grep -q '"bastion_root_until":"' || fail "no root banner in the state"
	owner state | grep -q '"action":"bastion_root"' && owner state | grep -q '"action":"bastion_cert_delivered"' || fail "root session not audited"
	ok "root: red card listed the open bucket, closed it before the certificate, one delivery, used through a real sshd"

	# --- a routine task queued by the agent: nothing runs before the tap ---
	"$AQMAS" bastion task journal-vacuum --keep-days 14 --why "interop: the journal is large" </dev/null >"$T/task.out" 2>"$T/task.err" &
	pid=$!
	id=$(owner wait setup interop-host 20)
	! grep -q 'vacuum' "$T/sys.log" || fail "a queued task ran before it was approved"
	owner approve-task "$id" 2>"$T/task-sign.err" || { cat "$T/task-sign.err"; fail "approve the queued task"; }
	wait $pid || { cat "$T/task.err"; fail "aqmas bastion task: $(cat "$T/task.out")"; }
	grep -q '^journalctl --rotate$' "$T/sys.log" && grep -q '^journalctl --vacuum-time=14d$' "$T/sys.log" || fail "the task's commands: $(cat "$T/sys.log")"
	grep -q 'done' "$T/task.err" || fail "task progress: $(cat "$T/task.err")"
	if "$AQMAS" bastion task journal-vacuum --keep-days 2 --why "too short" </dev/null >/dev/null 2>&1; then fail "the agent queued a short journal trim"; fi
	ok "a task queued by the agent ran only after the owner's tap, with the signed parameters"

	# --- updates: the kernel and boot chain are excluded unless the owner allows them ---
	owner setup-run os-update '{"kernel":false}'
	owner setup-wait os-update done 60 >"$T/update-result.json"
	grep -q -- '-- dnf -y --refresh upgrade --exclude=kernel\*' "$T/sys.log" || fail "dnf arguments: $(grep systemd-run "$T/sys.log")"
	grep -q 'bash' "$T/update-result.json" || fail "no summary of what changed: $(cat "$T/update-result.json")"
	ok "system update ran with the kernel excluded and reported what changed"

	# --- remove access: back to the emergency key only ---
	owner setup-run bastion-access-remove
	owner setup-wait bastion-access-remove done 60 >/dev/null
	! grep -q '^\[bastion\]' "$L/etc/config.toml" && grep -q 'comments must survive' "$L/etc/config.toml" || fail "[bastion] not removed"
	[[ ! -e $L/sysroot/etc/ssh/aqmas_user_ca.pub && ! -e $L/sysroot/etc/ssh/sshd_config.d/90-aqmas-inspect.conf && ! -e $L/sysroot/etc/ssh/aqmas_principals/$ME && ! -e $L/etc/bastion-allow.json && ! -e $T/inspect-account ]] || fail "removal left files: $(ls -R "$L/sysroot/etc/ssh")"
	owner login >/dev/null
	"$AQMAS" bastion 2>&1 | grep -q 'not installed' || fail "bastion access still offered after removal"
	ok "access to the bastion removed"
}
