// setcap gives one file the capability CAP_NET_BIND_SERVICE in its permitted and effective sets, as
// `setcap cap_net_bind_service=+ep <file>` does in upstream CoreDNS's Dockerfile - without
// installing libcap2-bin from an unpinned Debian mirror into the builder (app/coredns/Dockerfile).
//
// The capability is the file's `security.capability` extended attribute, a struct vfs_cap_data
// (linux/capability.h) at revision 2: magic_etc, then permitted/inheritable for capabilities 0-31
// and 32-63, all little-endian 32-bit words. Run as root in the build; written and read back, so a
// filesystem that silently drops the attribute fails the build instead of shipping a binary that
// cannot bind port 53.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

const (
	vfsCapRevision2     = 0x02000000
	vfsCapFlagEffective = 0x000001
	capNetBindService   = 10
	xattr               = "security.capability"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: setcap <file>")
		os.Exit(2)
	}
	path := os.Args[1]

	want := make([]byte, 20)
	binary.LittleEndian.PutUint32(want[0:], vfsCapRevision2|vfsCapFlagEffective)
	binary.LittleEndian.PutUint32(want[4:], 1<<capNetBindService) // permitted, 0-31
	// inheritable 0-31, permitted 32-63, inheritable 32-63: zero.

	if err := syscall.Setxattr(path, xattr, want, 0); err != nil {
		fmt.Fprintf(os.Stderr, "setcap: set %s on %s: %v\n", xattr, path, err)
		os.Exit(1)
	}
	got := make([]byte, 64)
	n, err := syscall.Getxattr(path, xattr, got)
	if err != nil || !bytes.Equal(got[:n], want) {
		fmt.Fprintf(os.Stderr, "setcap: %s on %s reads back as %x (err %v), want %x\n", xattr, path, got[:max(n, 0)], err, want)
		os.Exit(1)
	}
	fmt.Printf("%s: cap_net_bind_service=ep\n", path)
}
