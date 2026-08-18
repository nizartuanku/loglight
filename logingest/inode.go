package logingest

import (
	"os"
	"syscall"
)

// inodeOf returns the file's inode number on Unix, or 0 if unavailable. Used by
// the file tailer to detect log rotation (a new inode at the same path).
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
