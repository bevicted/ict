package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const tmpfsMagic = 0x01021994

func verifyAuthTmpfs(path string, maximumBytes, minimumFreeBytes int64) (string, error) {
	root, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("auth tmpfs directory is unavailable")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", errors.New("auth tmpfs directory is unavailable")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil || stat.Type != tmpfsMagic {
		return "", errors.New("auth state directory must be tmpfs")
	}
	blockSize := int64(stat.Bsize)
	if blockSize <= 0 || int64(stat.Blocks) > maximumBytes/blockSize || int64(stat.Bavail) < minimumFreeBytes/blockSize {
		return "", errors.New("auth tmpfs capacity contract is not met")
	}
	return root, nil
}
