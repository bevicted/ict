//go:build !linux

package workflow

import "errors"

// Production auth workers run on Linux. Non-Linux callers must inject an
// AuthTmpfsVerifier, keeping unit tests portable without weakening production.
func verifyAuthTmpfs(string, int64, int64) (string, error) {
	return "", errors.New("auth tmpfs verification is only available on Linux")
}
