#!/usr/bin/env bash
# install-host-trust.sh: make this fleet host's sshd accept aqmas SSH user certificates
# (docs/HOSTS.md). Dry run by default; --apply changes things. Never touches authorized_keys.
#
#   sudo ./install-host-trust.sh --name db-1 --ca-key aqmas_user_ca.pub            # dry run
#   sudo ./install-host-trust.sh --name db-1 --ca-key aqmas_user_ca.pub --apply
#   sudo ./install-host-trust.sh --uninstall [--name db-1] [--apply]
#
# Site policy (optional) comes from /etc/aqmas/host-trust.conf (--policy FILE to use another;
# see host-trust.conf.example) and from --refuse / --needs-approval:
#   refuse NAME|ADDRESS      never configure this host (e.g. the aqmas bastion)
#   needs-approval NAME      only with --i-have-owner-approval
#
# Installs (all root:root 0644, principals dir 0755):
#   /etc/ssh/aqmas_user_ca.pub             the CA public key given with --ca-key
#   /etc/ssh/aqmas_principals/<user>       one line: <user>@<name>
#   /etc/ssh/sshd_config.d/10-aqmas.conf   TrustedUserCAKeys + AuthorizedPrincipalsFile
# Backs up whatever it replaces to /var/backups/aqmas-host-trust/<UTC time>/, validates with
# `sshd -t` and checks `sshd -T` shows the new values before reloading sshd; on a failed check
# it restores the backup. Keep a second root session open while running it with --apply.
set -Eeuo pipefail
umask 022

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MARKER="# managed by aqmas install-host-trust.sh"

# Hosts this script must never configure (names, and addresses checked against `ip addr`),
# and hosts that need the owner's explicit go-ahead. Filled from the policy file and flags.
HARD_DENY=()
HARD_DENY_ADDRS=()
APPROVAL_DENY=()
POLICY=
POLICY_GIVEN=0

APPLY=0
MODE=install
ROOT=/
NAME=
CA_KEY=
CA_FP=
USERS=()
USERS_GIVEN=0
OWNER_OK=0
SSHD=
SYSTEMCTL=${SYSTEMCTL:-systemctl}

usage() {
	sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
	cat <<'EOF'

Options:
  --name NAME                  the host's name in aqmasd's [[targets]] (required for install)
  --ca-key FILE                the aqmas SSH user CA public key (required for install)
  --ca-fingerprint SHA256:...  refuse unless --ca-key has this fingerprint (as the owner read
                               it on the bastion: ssh-keygen -lf of aqmasd print-ssh-ca)
  --user USER                  login user to write a principals file for (default: $SUDO_USER;
                               repeatable; root is refused)
  --apply                      make the changes (default: dry run, print the plan)
  --uninstall                  remove what install created (dry run unless --apply)
  --i-have-owner-approval      allow hosts listed as needs-approval
  --policy FILE                site policy file (default /etc/aqmas/host-trust.conf, under --root
                               when given; missing default file = no policy)
  --refuse NAME|ADDRESS        never configure this host (repeatable)
  --needs-approval NAME        require --i-have-owner-approval for this host (repeatable)
  --root DIR                   operate on DIR instead of / (tests); never reloads sshd
  --sshd PATH                  sshd binary for -t/-T (default: sshd; skipped with --root unless given)
EOF
}

die() { echo "install-host-trust: error: $*" >&2; exit 1; }
say() { echo "install-host-trust: $*"; }

# add_refuse NAME|ADDRESS: an IPv4/IPv6 address goes to the address list, anything else is a name.
add_refuse() {
	[[ -n $1 ]] || die "--refuse needs a host name or address"
	if [[ $1 =~ ^[0-9.]+$ || $1 == *:* ]]; then HARD_DENY_ADDRS+=("$1"); else HARD_DENY+=("$1"); fi
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--apply) APPLY=1 ;;
	--uninstall) MODE=uninstall ;;
	--name) NAME=${2:-}; shift ;;
	--name=*) NAME=${1#*=} ;;
	--ca-key) CA_KEY=${2:-}; shift ;;
	--ca-key=*) CA_KEY=${1#*=} ;;
	--ca-fingerprint) CA_FP=${2:-}; shift ;;
	--ca-fingerprint=*) CA_FP=${1#*=} ;;
	--user) USERS+=("${2:-}"); USERS_GIVEN=1; shift ;;
	--user=*) USERS+=("${1#*=}"); USERS_GIVEN=1 ;;
	--root) ROOT=${2:-}; shift ;;
	--root=*) ROOT=${1#*=} ;;
	--sshd) SSHD=${2:-}; shift ;;
	--sshd=*) SSHD=${1#*=} ;;
	--i-have-owner-approval) OWNER_OK=1 ;;
	--policy) POLICY=${2:-}; POLICY_GIVEN=1; shift ;;
	--policy=*) POLICY=${1#*=}; POLICY_GIVEN=1 ;;
	--refuse) add_refuse "${2:-}"; shift ;;
	--refuse=*) add_refuse "${1#*=}" ;;
	--needs-approval) APPROVAL_DENY+=("${2:-}"); shift ;;
	--needs-approval=*) APPROVAL_DENY+=("${1#*=}") ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
	shift
done
if [[ ${#USERS[@]} -eq 0 && -n ${SUDO_USER:-} && ${SUDO_USER} != root ]]; then
	USERS=("$SUDO_USER")
elif [[ ${#USERS[@]} -eq 0 && $MODE == install ]]; then
	die "--user is required (no non-root \$SUDO_USER to default to)"
fi

[[ -n $ROOT && -d $ROOT ]] || die "--root $ROOT is not a directory"
# Physical path, so "//" or a symlink to / cannot pose as a test root and skip the checks
# and the sshd validation that apply to the real system.
ROOT=$(cd "$ROOT" && pwd -P)
[[ ! $ROOT =~ ^/+$ ]] || ROOT=/ # bash keeps "//" as is
R=${ROOT%/} # prefix for paths; empty for the real system
if [[ -z $SSHD && -z $R ]]; then SSHD=$(command -v sshd || echo /usr/sbin/sshd); fi

# Site policy file: "refuse NAME|ADDRESS" and "needs-approval NAME" lines, '#' comments.
[[ $POLICY_GIVEN -eq 1 ]] || POLICY=$R/etc/aqmas/host-trust.conf
if [[ -e $POLICY || $POLICY_GIVEN -eq 1 ]]; then
	[[ -r $POLICY ]] || die "cannot read policy file $POLICY"
	lineno=0
	while IFS= read -r line || [[ -n $line ]]; do
		lineno=$((lineno + 1))
		line=${line%%#*}
		read -r kw arg extra <<<"$line" || true
		[[ -n ${kw:-} ]] || continue
		[[ -n ${arg:-} && -z ${extra:-} ]] || die "$POLICY:$lineno: want '<refuse|needs-approval> <host>'"
		case $kw in
		refuse) add_refuse "$arg" ;;
		needs-approval) APPROVAL_DENY+=("$arg") ;;
		*) die "$POLICY:$lineno: unknown keyword '$kw'" ;;
		esac
	done <"$POLICY"
fi

ETC_SSH=$R/etc/ssh
CA_DST=$ETC_SSH/aqmas_user_ca.pub
PRINC_DIR=$ETC_SSH/aqmas_principals
CONF_DIR=$ETC_SSH/sshd_config.d
CONF_DST=$CONF_DIR/10-aqmas.conf
CONF_SRC=$SCRIPT_DIR/10-aqmas.conf
SSHD_CONFIG=$ETC_SSH/sshd_config
BACKUP_ROOT=$R/var/backups/aqmas-host-trust

# ---- checks that apply to every mode ----

[[ -z $NAME || $NAME =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "--name '$NAME' is not a plain lowercase host name"
for u in ${USERS[@]+"${USERS[@]}"}; do
	[[ $u =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--user '$u' is not a valid login name"
	[[ $u != root ]] || die "refusing a principals file for root"
done

if [[ $APPLY -eq 1 && -z $R && $EUID -ne 0 ]]; then
	die "--apply on the real system needs root (sudo)"
fi

# Names this host goes by: --name, the system host name, $ROOT/etc/hostname.
host_names=()
[[ -n $NAME ]] && host_names+=("$NAME")
if [[ -r $R/etc/hostname ]]; then host_names+=("$(head -n1 "$R/etc/hostname" | cut -d. -f1)"); fi
# The machine we run on is checked even with --root.
host_names+=("$(hostname -s 2>/dev/null || uname -n)")
for h in "${host_names[@]}"; do
	for d in ${HARD_DENY[@]+"${HARD_DENY[@]}"}; do
		[[ $h != "$d" ]] || die "refusing to run on $d: the site policy refuses it (e.g. the aqmas bastion)"
	done
	for d in ${APPROVAL_DENY[@]+"${APPROVAL_DENY[@]}"}; do
		if [[ $h == "$d" && $OWNER_OK -ne 1 ]]; then
			die "$d needs the owner's go-ahead; re-run with --i-have-owner-approval once you have it"
		fi
	done
done
if command -v ip >/dev/null; then
	addrs=$(ip -o addr show 2>/dev/null || true)
	for a in ${HARD_DENY_ADDRS[@]+"${HARD_DENY_ADDRS[@]}"}; do
		if grep -qF " $a/" <<<"$addrs"; then die "refusing to run on $a: the site policy refuses it (e.g. the aqmas bastion)"; fi
	done
fi

# ---- helpers ----

# plan_file DEST CONTENT: prints what would happen to DEST and records it in CHANGES.
CHANGES=()
plan_file() {
	local dest=$1 content=$2
	if [[ -f $dest ]] && [[ "$(cat "$dest")" == "$content" ]]; then
		say "unchanged  ${dest#"$R"}"
	elif [[ -e $dest ]]; then
		say "replace    ${dest#"$R"} (backed up first)"
		CHANGES+=("$dest")
	else
		say "create     ${dest#"$R"}"
		CHANGES+=("$dest")
	fi
}

# backup FILES...: copies each existing file into BACKUP (relative to ROOT); records absent ones.
# From then on any unexpected failure restores the backup (ERR trap; set -E covers functions).
BACKUP=
on_err() {
	local rc=$?
	trap - ERR
	say "unexpected failure (exit $rc)"
	if [[ -n $BACKUP && -f $BACKUP/MANIFEST ]]; then restore; fi
	exit "$rc"
}
backup() {
	BACKUP=$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$
	mkdir -p "$BACKUP"
	chmod 700 "$BACKUP_ROOT" "$BACKUP"
	local f
	for f in "$@"; do
		if [[ -e $f ]]; then
			mkdir -p "$BACKUP/files$(dirname "${f#"$R"}")"
			cp -a "$f" "$BACKUP/files${f#"$R"}"
			echo "existed ${f#"$R"}" >>"$BACKUP/MANIFEST"
		else
			echo "absent ${f#"$R"}" >>"$BACKUP/MANIFEST"
		fi
	done
	say "backup     ${BACKUP#"$R"}"
	trap on_err ERR
}

restore() {
	say "restoring from ${BACKUP#"$R"}"
	local state path
	while read -r state path; do
		case $state in
		existed) cp -a "$BACKUP/files$path" "$R$path" ;;
		absent) rm -f "$R$path" ;;
		esac
	done <"$BACKUP/MANIFEST"
	rmdir "$PRINC_DIR" 2>/dev/null || true
}

# put DEST CONTENT: atomic write, 0644, root-owned when we are root.
put() {
	local dest=$1 content=$2 tmp
	tmp=$(mktemp "$(dirname "$dest")/.aqmas-tmp.XXXXXX")
	printf '%s\n' "$content" >"$tmp"
	chmod 0644 "$tmp"
	if [[ $EUID -eq 0 ]]; then chown root:root "$tmp"; fi
	mv -f "$tmp" "$dest"
}

sshd_check() {
	if [[ -z $SSHD ]]; then
		say "skip       sshd -t / sshd -T (--root without --sshd)"
		return 0
	fi
	local cfg=()
	[[ -z $R ]] || cfg=(-f "$SSHD_CONFIG")
	# ${cfg[@]+...}: an empty array is "unbound" under set -u in bash < 4.4 (macOS /bin/bash).
	if ! "$SSHD" -t ${cfg[@]+"${cfg[@]}"}; then
		say "sshd -t failed"
		return 1
	fi
	say "ok         sshd -t"
	[[ $MODE == install ]] || return 0
	local eff u
	for u in ${USERS[@]+"${USERS[@]}"}; do
		eff=$("$SSHD" -T ${cfg[@]+"${cfg[@]}"} -C "user=$u,host=${NAME},addr=192.0.2.50" 2>&1) || { say "sshd -T failed: $eff"; return 1; }
		if ! grep -qxi "trustedusercakeys /etc/ssh/aqmas_user_ca.pub" <<<"$eff" ||
			! grep -qxi "authorizedprincipalsfile /etc/ssh/aqmas_principals/%u" <<<"$eff"; then
			say "sshd -T for user $u does not show the aqmas values (another setting wins):"
			grep -iE "^(trustedusercakeys|authorizedprincipals)" <<<"$eff" >&2 || true
			return 1
		fi
	done
	say "ok         sshd -T shows TrustedUserCAKeys and AuthorizedPrincipalsFile"
}

reload_sshd() {
	if [[ -n $R ]]; then
		say "skip       reload sshd (--root)"
		return 0
	fi
	local unit
	for unit in sshd ssh; do
		if "$SYSTEMCTL" is-active --quiet "$unit.service" 2>/dev/null; then
			"$SYSTEMCTL" reload "$unit.service"
			say "reloaded   $unit.service (existing sessions stay up)"
			wait_sshd_listening
			return 0
		fi
	done
	say "WARNING: no active sshd.service/ssh.service found; reload sshd yourself"
}

# A reload can briefly close sshd's listening socket (seen on Fedora: a login right after the
# reload got "connection refused"). Wait up to SSHD_WAIT_SECONDS (10) for every configured port
# to listen again before reporting success.
wait_sshd_listening() {
	local ports port waited=0 limit=${SSHD_WAIT_SECONDS:-10} missing
	ports=$("$SSHD" -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}' | sort -u) || true
	[[ -n $ports ]] || ports=22
	while :; do
		missing=
		for port in $ports; do
			if command -v ss >/dev/null 2>&1; then
				[[ -n $(ss -Hltn "sport = :$port" 2>/dev/null) ]] || missing+=" $port"
			else
				(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || missing+=" $port"
			fi
		done
		if [[ -z $missing ]]; then
			say "ok         sshd listening on port(s) $(echo $ports) after ${waited} s"
			return 0
		fi
		if ((waited >= limit)); then
			die "sshd is not listening on port(s)$missing ${limit} s after the reload; the new config IS in place. From your second root session check: systemctl status sshd; ss -ltn"
		fi
		sleep 1
		waited=$((waited + 1))
	done
}

# conflicts: other sshd config lines that would win over ours (sshd keeps the first value).
check_conflicts() {
	if [[ ! -r $SSHD_CONFIG ]]; then
		if [[ $APPLY -eq 1 ]]; then die "cannot read ${SSHD_CONFIG#"$R"}"; fi
		say "note       cannot read ${SSHD_CONFIG#"$R"} as $(id -un); conflicts are checked with --apply (run with sudo)"
		return 0
	fi
	# The drop-in directory must be included, and before any Match block.
	local inc
	inc=$(awk 'tolower($1)=="match"{exit} tolower($1)=="include" && $2 ~ /sshd_config\.d\/\*\.conf$/ {print NR; exit}' "$SSHD_CONFIG")
	[[ -n $inc ]] || die "${SSHD_CONFIG#"$R"} has no 'Include /etc/ssh/sshd_config.d/*.conf' before its first Match block"
	local f hits=""
	for f in "$SSHD_CONFIG" "$CONF_DIR"/*.conf; do
		[[ -f $f && $f != "$CONF_DST" ]] || continue
		if grep -qiE '^[[:space:]]*(TrustedUserCAKeys|AuthorizedPrincipalsFile|AuthorizedPrincipalsCommand)[[:space:]]' "$f"; then
			hits+=$'\n'"  ${f#"$R"}: $(grep -iE '^[[:space:]]*(TrustedUserCAKeys|AuthorizedPrincipalsFile|AuthorizedPrincipalsCommand)[[:space:]]' "$f" | tr '\n' ';')"
		fi
	done
	[[ -z $hits ]] || die "other sshd config already sets these (resolve by hand first):$hits"
	say "ok         no conflicting TrustedUserCAKeys/AuthorizedPrincipals* settings"
}

# ---- install ----

do_install() {
	[[ -n $NAME ]] || die "--name is required (the host's name in aqmasd's [[targets]])"
	[[ -n $CA_KEY ]] || die "--ca-key FILE is required"
	[[ -f $CA_KEY && -r $CA_KEY ]] || die "--ca-key $CA_KEY is not a readable file"
	[[ -f $CONF_SRC ]] || die "missing $CONF_SRC"
	[[ -d $ETC_SSH ]] || die "${ETC_SSH#"$R"} does not exist"

	# Exactly one plain public key line: no options, not a certificate, not a private key.
	local lines key_line
	lines=$(grep -vE '^[[:space:]]*(#|$)' "$CA_KEY" || true)
	[[ -n $lines && $(wc -l <<<"$lines") -eq 1 ]] || die "--ca-key must hold exactly one public key line"
	key_line=$lines
	# aqmasd's SSH user CA is always Ed25519 (internal/server/pki).
	[[ $key_line =~ ^ssh-ed25519\ [A-Za-z0-9+/]+=*(\ [[:print:]]*)?$ ]] ||
		die "--ca-key is not a plain ssh-ed25519 public key line (aqmasd print-ssh-ca)"
	if command -v ssh-keygen >/dev/null; then
		ssh-keygen -l -f "$CA_KEY" >/dev/null 2>&1 || die "ssh-keygen cannot read --ca-key"
		local fp
		fp=$(ssh-keygen -l -f "$CA_KEY" | cut -d' ' -f2)
		say "CA key     $(ssh-keygen -l -f "$CA_KEY")"
		if [[ -n $CA_FP && $fp != "$CA_FP" ]]; then
			die "--ca-key fingerprint $fp is not the expected $CA_FP"
		fi
	elif [[ -n $CA_FP ]]; then
		die "--ca-fingerprint needs ssh-keygen"
	fi

	check_conflicts

	local conf
	conf=$(cat "$CONF_SRC")
	plan_file "$CA_DST" "$key_line"
	plan_file "$CONF_DST" "$conf"
	local u
	for u in ${USERS[@]+"${USERS[@]}"}; do
		plan_file "$PRINC_DIR/$u" "$u@$NAME"
	done
	if [[ -d $PRINC_DIR ]]; then :; else say "create     ${PRINC_DIR#"$R"}/ (0755)"; fi

	if [[ ${#CHANGES[@]} -eq 0 ]]; then
		say "nothing to change"
		if [[ $APPLY -eq 1 ]]; then sshd_check || die "sshd config check failed (nothing was changed by this run)"; fi
		return 0
	fi
	if [[ $APPLY -ne 1 ]]; then
		say "dry run: nothing changed. Re-run with --apply to make these changes."
		return 0
	fi

	backup "${CHANGES[@]}"
	mkdir -p "$PRINC_DIR" "$CONF_DIR"
	chmod 0755 "$PRINC_DIR"
	if [[ $EUID -eq 0 ]]; then chown root:root "$PRINC_DIR"; fi
	put "$CA_DST" "$key_line"
	for u in ${USERS[@]+"${USERS[@]}"}; do put "$PRINC_DIR/$u" "$u@$NAME"; done
	put "$CONF_DST" "$conf"
	if ! sshd_check; then
		restore
		die "sshd config check failed; restored the previous files, sshd was not reloaded"
	fi
	reload_sshd
	say "done. Now test from another host: a certificate login (aqmas ssh ${USERS[0]}@$NAME) AND a plain key login."
}

# ---- uninstall ----

do_uninstall() {
	local targets=() f u
	if [[ -f $CONF_DST ]]; then
		grep -qF "$MARKER" "$CONF_DST" || die "${CONF_DST#"$R"} was not written by this script; leaving it alone"
		targets+=("$CONF_DST")
	fi
	if [[ -f $CA_DST ]]; then
		[[ $(grep -cvE '^[[:space:]]*(#|$)' "$CA_DST") -eq 1 ]] &&
			grep -qE '^(ssh-|ecdsa-|sk-|rsa-)[^ ]+ [A-Za-z0-9+/]+=*( |$)' "$CA_DST" ||
			die "${CA_DST#"$R"} is not a single public key line as this script writes it; leaving it alone"
		targets+=("$CA_DST")
	fi
	# Without --user, every principals file this script could have written.
	local users=(${USERS[@]+"${USERS[@]}"})
	if [[ $USERS_GIVEN -eq 0 && -d $PRINC_DIR ]]; then
		users=()
		for f in "$PRINC_DIR"/*; do [[ -f $f ]] && users+=("$(basename "$f")"); done
	fi
	for u in ${users[@]+"${users[@]}"}; do
		f=$PRINC_DIR/$u
		[[ -f $f ]] || continue
		if [[ -n $NAME ]]; then
			[[ "$(cat "$f")" == "$u@$NAME" ]] || die "${f#"$R"} does not hold exactly '$u@$NAME'; leaving it alone"
		else
			[[ $u =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$(cat "$f")" =~ ^$u@[a-z0-9-]+$ ]] ||
				die "${f#"$R"} has unexpected content; leaving it alone"
		fi
		targets+=("$f")
	done
	if [[ ${#targets[@]} -eq 0 ]]; then
		say "nothing to remove"
		return 0
	fi
	for f in "${targets[@]}"; do say "remove     ${f#"$R"}"; done
	if [[ $APPLY -ne 1 ]]; then
		say "dry run: nothing changed. Re-run with --uninstall --apply to remove these."
		return 0
	fi
	backup "${targets[@]}"
	rm -f "${targets[@]}"
	rmdir "$PRINC_DIR" 2>/dev/null || true
	if ! sshd_check; then
		restore
		die "sshd config check failed after removal; restored the files, sshd was not reloaded"
	fi
	reload_sshd
	say "done. aqmas certificate logins are no longer accepted here."
}

case $MODE in
install) do_install ;;
uninstall) do_uninstall ;;
esac
