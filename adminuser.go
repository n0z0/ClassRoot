package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

const adminUsername = "admin"

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func generatePassword(n int) (string, error) {
	b := make([]byte, n)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = passwordAlphabet[v.Int64()]
	}
	return string(b), nil
}

// plainPassword extracts a cleartext password from a group user entry,
// which may be either a bare string or {"type":"plain","key":"..."}.
func plainPassword(v any) (string, bool) {
	switch p := v.(type) {
	case string:
		return p, p != ""
	case map[string]any:
		t, _ := p["type"].(string)
		k, _ := p["key"].(string)
		if (t == "" || t == "plain") && k != "" {
			return k, true
		}
	}
	return "", false
}

// groupCredential is a user's cleartext password as stored in a group
// file.  Hashed is true when the stored password is hashed and cannot
// be shown.
type groupCredential struct {
	Password string
	Hashed   bool
}

// resolvePassword returns the cleartext password of entry, generating
// one if it has none (or only a wildcard password).  changed reports
// whether entry was modified.
func resolvePassword(entry map[string]any) (cred groupCredential, changed bool, err error) {
	if pw, ok := plainPassword(entry["password"]); ok {
		return groupCredential{Password: pw}, false, nil
	}
	pwType := ""
	if m, ok := entry["password"].(map[string]any); ok {
		pwType, _ = m["type"].(string)
	}
	if entry["password"] != nil && pwType != "wildcard" {
		return groupCredential{Hashed: true}, false, nil
	}
	pw, err := generatePassword(12)
	if err != nil {
		return groupCredential{}, false, err
	}
	entry["password"] = pw
	return groupCredential{Password: pw}, true, nil
}

// isWildcardPassword reports whether v is {"type":"wildcard"}.
func isWildcardPassword(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	t, _ := m["type"].(string)
	return t == "wildcard" && len(m) == 1
}

// ensureGroupCredentials makes sure the group file has an "admin" user
// with "op" permission, whose password is generated once and saved so
// it stays the same across restarts, and a wildcard user ("present")
// that accepts any non-empty password.
func ensureGroupCredentials(groupFile string) (admin groupCredential, err error) {
	data, err := os.ReadFile(groupFile)
	if err != nil {
		return admin, err
	}
	var desc map[string]any
	if err := json.Unmarshal(data, &desc); err != nil {
		return admin, fmt.Errorf("%s: %w", filepath.Base(groupFile), err)
	}

	users, _ := desc["users"].(map[string]any)
	if users == nil {
		users = make(map[string]any)
	}
	adminEntry, _ := users[adminUsername].(map[string]any)
	if adminEntry == nil {
		adminEntry = make(map[string]any)
	}
	changed := false
	if adminEntry["permissions"] != "op" {
		adminEntry["permissions"] = "op"
		changed = true
	}
	admin, c, err := resolvePassword(adminEntry)
	if err != nil {
		return admin, err
	}
	changed = changed || c
	users[adminUsername] = adminEntry
	desc["users"] = users

	// Presenter: username dan password bebas.
	wildEntry, _ := desc["wildcard-user"].(map[string]any)
	if wildEntry == nil {
		wildEntry = map[string]any{"permissions": "present"}
		changed = true
	}
	if !isWildcardPassword(wildEntry["password"]) {
		wildEntry["password"] = map[string]any{"type": "wildcard"}
		changed = true
	}
	desc["wildcard-user"] = wildEntry

	if !changed {
		return admin, nil
	}

	out, err := json.MarshalIndent(desc, "", "  ")
	if err != nil {
		return admin, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(groupFile, out, 0600); err != nil {
		return admin, err
	}
	// The file holds a cleartext password: keep it private.
	_ = os.Chmod(groupFile, 0600)
	return admin, nil
}
