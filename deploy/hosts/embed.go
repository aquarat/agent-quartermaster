package hosts

import _ "embed"

// The host-trust installer and the sshd drop-in it installs, embedded so the maintenance
// runner configures the bastion's own sshd with exactly the release's files.

//go:embed install-host-trust.sh
var InstallScript []byte

//go:embed 10-aqmas.conf
var TrustConf []byte
