//go:build !windows

package tsync

import (
	"errors"
	"os"
	"syscall"
)

func osGetFreeSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

// syncDir fsyncs a directory so renames into it survive a crash.
// Filesystems that do not support directory fsync (EINVAL/ENOTSUP) are ignored.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) && !errors.Is(syncErr, syscall.ENOTSUP) {
		return syncErr
	}
	return closeErr
}
