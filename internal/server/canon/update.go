package canon

import "github.com/aquarat/agent-quartermaster/internal/release"

type Update struct {
	FromVersion string `json:"from_version"`
	FromCommit  string `json:"from_commit"`
	ToVersion   string `json:"to_version"`
	ToCommit    string `json:"to_commit"`
	DaemonHash  string `json:"daemon_sha256"`
	LinuxARM    string `json:"linux_arm64_sha256"`
	LinuxAMD    string `json:"linux_amd64_sha256"`
	DarwinARM   string `json:"darwin_arm64_sha256"`
}

func (u Update) Sums() release.Sums {
	return release.Sums{release.Daemon: u.DaemonHash, "aqmas-linux-arm64": u.LinuxARM, "aqmas-linux-amd64": u.LinuxAMD, "aqmas-darwin-arm64": u.DarwinARM}
}
