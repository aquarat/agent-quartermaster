// Package bastion carries the root-owned files the maintenance runner installs itself, so
// they always match the release that is running.
package bastion

import _ "embed"

//go:embed aqmas-lock-alert.py
var LockAlertScript []byte

//go:embed aqmas-lock-alert.service
var LockAlertUnit []byte

//go:embed aqmas-maint.service
var MaintUnit []byte

//go:embed aqmas-maint.path
var MaintPath []byte
