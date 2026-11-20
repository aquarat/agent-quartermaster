#!/usr/bin/env bash
# Install aqmasd on the bastion (192.0.2.60).
#
# By default this only PRINTS the steps. With --apply it runs them on the machine it is run on
# (it never connects anywhere else), and every step is idempotent: existing config, keys and
# data are never overwritten. Run it on the bastion as root, from a checkout or a copy of
# deploy/bastion/ plus the aqmasd binary:
#
#   sudo ./install.sh --binary ./aqmasd-linux-arm64            # show the plan
#   sudo ./install.sh --binary ./aqmasd-linux-arm64 --apply    # do it
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
binary=""
apply=0
expect_host="bastion"

while [ $# -gt 0 ]; do
	case "$1" in
	--binary) binary="$2"; shift 2 ;;
	--apply) apply=1; shift ;;
	--any-host) expect_host=""; shift ;;
	-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

run() {
	if [ "$apply" = 1 ]; then
		echo "+ $*"
		"$@"
	else
		echo "  $*"
	fi
}

if [ "$apply" = 1 ]; then
	[ "$(id -u)" = 0 ] || { echo "--apply needs root" >&2; exit 1; }
	if [ -n "$expect_host" ] && [ "$(hostname -s)" != "$expect_host" ]; then
		echo "this is $(hostname -s), not $expect_host; refusing (use --any-host to override)" >&2
		exit 1
	fi
	[ -n "$binary" ] && [ -x "$binary" ] || { echo "--binary <path to aqmasd> required" >&2; exit 1; }
else
	echo "Plan (dry run; add --apply to execute on this machine):"
fi

# 1. System user.
if ! id aqmas >/dev/null 2>&1; then
	run useradd --system --user-group --home-dir /var/lib/aqmas --no-create-home --shell /usr/sbin/nologin aqmas
fi

# 2. Binary.
run install -o root -g root -m 0755 "${binary:-./aqmasd-linux-arm64}" /usr/local/bin/aqmasd

# 3. Config (never overwritten).
run install -d -o root -g aqmas -m 0750 /etc/aqmas
if [ ! -e /etc/aqmas/config.toml ]; then
	run install -o root -g aqmas -m 0640 "$here/config.example.toml" /etc/aqmas/config.toml
else
	echo "  (keeping existing /etc/aqmas/config.toml)"
fi

# 4. systemd unit (data dir /var/lib/aqmas is created by StateDirectory=, mode 0700).
run install -o root -g root -m 0644 "$here/aqmasd.service" /etc/systemd/system/aqmasd.service
run systemctl daemon-reload

cat <<'NEXT'

Next steps (by hand, on the bastion):
  1. Edit /etc/aqmas/config.toml: targets (+ host_key pins), ntfy topic, access.team_domain/aud.
  2. Open the agent API to the LAN only:
       firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.0.2.0/24 port port=8443 protocol=tcp accept'
       firewall-cmd --reload
  3. systemctl enable --now aqmasd && journalctl -u aqmasd -n 20
     (first start generates /var/lib/aqmas/ca/*: SSH user CA, client CA, server cert)
  4. sudo -u aqmas aqmasd print-ssh-ca       -> /etc/ssh/aqmas_user_ca.pub on fleet hosts (docs/HOSTS.md)
     sudo -u aqmas aqmasd tls-fingerprint    -> the pin for `aqmas enroll --ca-pin` (sha256:<hex>)
  5. Tunnel: cloudflared-aqmas.yml.example -> /etc/cloudflared/aqmas.yml, cloudflared-aqmas.service
     -> /etc/systemd/system/, then systemctl enable --now cloudflared-aqmas. Put an Access app
     (owner, OIDC IdP) on approvals.example.com.
  6. sudo -u aqmas aqmasd passkey-enroll-code, open https://approvals.example.com within 15 minutes
     and register the owner passkey.
  7. Cloudflare (optional, milestone 2; docs/DEPLOY-M2.md): put the parent tokens in
     /etc/aqmas/cf-proxy-token and /etc/aqmas/cf-minter-token (root:root 0600), add the
     LoadCredential= drop-in described in aqmasd.service, fill [cloudflare] in config.toml,
     then systemctl daemon-reload && systemctl restart aqmasd.
NEXT
