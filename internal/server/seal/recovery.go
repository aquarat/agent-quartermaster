package seal

import (
	"bytes"
	"io"
	"strings"

	"filippo.io/age"
)

func (i Inventory) OfflineProof(identity []byte) (string, error) {
	mk, err := i.offlineKey(identity)
	if err != nil {
		return "", err
	}
	defer mk.Destroy()
	return i.DrillProof(mk)
}
func (i Inventory) offlineKey(identity []byte) (*Key, error) {
	var key *age.X25519Identity
	for _, line := range strings.Split(string(identity), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key != nil {
			return nil, errRecord
		}
		var err error
		key, err = age.ParseX25519Identity(line)
		if err != nil {
			return nil, errRecord
		}
	}
	return i.Recover(i.Recipient, key, i.Recovery, i.Check)
}

// Transfer writes only to a protected pipe selected by the owner-side CLI.
func (i Inventory) Transfer(identity []byte, w io.Writer) error {
	k, err := i.offlineKey(identity)
	if err != nil {
		return err
	}
	defer k.Destroy()
	if err = i.VerifyInventory(k); err != nil {
		return err
	}
	_, err = w.Write(k.page[:32])
	return err
}
func (i Inventory) Receive(r io.Reader) (*Key, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(r, k.page[:32])
	if err == nil {
		err = i.VerifyInventory(k)
	}
	if err != nil {
		k.Destroy()
		return nil, err
	}
	return k, nil
}

// RecoveryPacket accepts only the canonical native X25519 public recipient.
func (g Generation) RecoveryPacket(recipient string, mk *Key) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if !g.valid() || err != nil || r.String() != recipient || mk == nil || mk.page == nil {
		return nil, errRecord
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	b := tuple("mk-recovery", g.Installation[:], number(g.Version), []byte(recipient), mk.page[:32])
	defer clear(b)
	if _, err = w.Write(b); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Recover is for isolated recovery/drill tools, never the web process. The
// expected recipient and generation come from the independent owner record.
func (g Generation) Recover(recipient string, identity *age.X25519Identity, packet, check []byte) (*Key, error) {
	if !g.valid() || identity == nil || identity.Recipient().String() != recipient || len(packet) > 4096 {
		return nil, errRecord
	}
	r, err := age.Decrypt(bytes.NewReader(packet), identity)
	if err != nil {
		return nil, errRecord
	}
	prefix := tuple("mk-recovery", g.Installation[:], number(g.Version), []byte(recipient))
	expected := len(prefix) + 4 + 32
	b, err := io.ReadAll(io.LimitReader(r, int64(expected+1)))
	defer clear(b)
	if err != nil || len(b) != expected || !bytes.Equal(b[:len(prefix)], prefix) || !bytes.Equal(b[len(prefix):len(prefix)+4], []byte{0, 0, 0, 32}) {
		return nil, errRecord
	}
	mk, err := importKey(b[len(b)-32:])
	if err != nil {
		return nil, err
	}
	if err = g.Verify(mk, check); err != nil {
		mk.Destroy()
		return nil, err
	}
	return mk, nil
}
