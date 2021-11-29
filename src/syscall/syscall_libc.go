//go:build darwin || nintendoswitch || wasi
// +build darwin nintendoswitch wasi

package syscall

import (
	"unsafe"
)

type sliceHeader struct {
	buf *byte
	len uintptr
	cap uintptr
}

func Close(fd int) (err error) {
	if libc_close(int32(fd)) < 0 {
		err = getErrno()
	}
	return
}

func Write(fd int, p []byte) (n int, err error) {
	buf, count := splitSlice(p)
	n = libc_write(int32(fd), buf, uint(count))
	if n < 0 {
		err = getErrno()
	}
	return
}

func Read(fd int, p []byte) (n int, err error) {
	buf, count := splitSlice(p)
	n = libc_read(int32(fd), buf, uint(count))
	if n < 0 {
		err = getErrno()
	}
	return
}

func Seek(fd int, offset int64, whence int) (off int64, err error) {
	return 0, ENOSYS // TODO
}

func Open(path string, flag int, mode uint32) (fd int, err error) {
	data := cstring(path)
	fd = int(libc_open(&data[0], int32(flag), mode))
	if fd < 0 {
		err = getErrno()
	}
	return
}

func Mkdir(path string, mode uint32) (err error) {
	data := cstring(path)
	fail := int(libc_mkdir(&data[0], mode))
	if fail < 0 {
		err = getErrno()
	}
	return
}

func Rmdir(path string) (err error) {
	data := cstring(path)
	fail := int(libc_rmdir(&data[0]))
	if fail < 0 {
		err = getErrno()
	}
	return
}

type Timespec struct {
	Sec  int64
	Nsec int64
}

// Go chose Linux's field names for Stat_t, see https://github.com/golang/go/issues/31735
type Stat_t struct {
	Dev       int32
	Mode      uint16
	Nlink     uint16
	Ino       uint64
	Uid       uint32
	Gid       uint32
	Rdev      int32
	Pad_cgo_0 [4]byte
	Atim      Timespec
	Mtim      Timespec
	Ctim      Timespec
	Btim      Timespec
	Size      int64
	Blocks    int64
	Blksize   int32
	Flags     uint32
	Gen       uint32
	Lspare    int32
	Qspare    [2]int64
}

// Source: https://github.com/apple/darwin-xnu/blob/main/bsd/sys/_types/_s_ifmt.h
// Consistent with values we use from lib/wasi-libc/sysroot/include/sys/stat.h
const (
	S_IEXEC  = 0x40
	S_IFBLK  = 0x6000
	S_IFCHR  = 0x2000
	S_IFDIR  = 0x4000
	S_IFIFO  = 0x1000
	S_IFLNK  = 0xa000
	S_IFMT   = 0xf000
	S_IFREG  = 0x8000
	S_IFSOCK = 0xc000
	S_IFWHT  = 0xe000
	S_IREAD  = 0x100
	S_IRGRP  = 0x20
	S_IROTH  = 0x4
	S_IRUSR  = 0x100
	S_IRWXG  = 0x38
	S_IRWXO  = 0x7
	S_IRWXU  = 0x1c0
	S_ISGID  = 0x400
	S_ISTXT  = 0x200
	S_ISUID  = 0x800
	S_ISVTX  = 0x200
	S_IWGRP  = 0x10
	S_IWOTH  = 0x2
	S_IWRITE = 0x80
	S_IWUSR  = 0x80
	S_IXGRP  = 0x8
	S_IXOTH  = 0x1
	S_IXUSR  = 0x40
)

func Stat(path string, p *Stat_t) (err error) {
	data := cstring(path)
	n := libc_stat(&data[0], unsafe.Pointer(p))

	if n < 0 {
		err = getErrno()
	}
	return
}

func Lstat(path string, p *Stat_t) (err error) {
	data := cstring(path)
	n := libc_lstat(&data[0], unsafe.Pointer(p))
	if n < 0 {
		err = getErrno()
	}
	return
}

func Unlink(path string) (err error) {
	data := cstring(path)
	fail := int(libc_unlink(&data[0]))
	if fail < 0 {
		err = getErrno()
	}
	return
}

func Kill(pid int, sig Signal) (err error) {
	return ENOSYS // TODO
}

type SysProcAttr struct{}

func Pipe2(p []int, flags int) (err error) {
	return ENOSYS // TODO
}

func Getenv(key string) (value string, found bool) {
	data := cstring(key)
	raw := libc_getenv(&data[0])
	if raw == nil {
		return "", false
	}

	ptr := uintptr(unsafe.Pointer(raw))
	for size := uintptr(0); ; size++ {
		v := *(*byte)(unsafe.Pointer(ptr))
		if v == 0 {
			src := *(*[]byte)(unsafe.Pointer(&sliceHeader{buf: raw, len: size, cap: size}))
			return string(src), true
		}
		ptr += unsafe.Sizeof(byte(0))
	}
}

func Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	addr := libc_mmap(nil, uintptr(length), int32(prot), int32(flags), int32(fd), uintptr(offset))
	if addr == unsafe.Pointer(^uintptr(0)) {
		return nil, getErrno()
	}
	return (*[1 << 30]byte)(addr)[:length:length], nil
}

func Mprotect(b []byte, prot int) (err error) {
	errCode := libc_mprotect(unsafe.Pointer(&b[0]), uintptr(len(b)), int32(prot))
	if errCode != 0 {
		err = getErrno()
	}
	return
}

func Environ() []string {
	environ := libc_environ
	var envs []string
	for *environ != nil {
		// Convert the C string to a Go string.
		length := libc_strlen(*environ)
		var envVar string
		rawEnvVar := (*struct {
			ptr    unsafe.Pointer
			length uintptr
		})(unsafe.Pointer(&envVar))
		rawEnvVar.ptr = *environ
		rawEnvVar.length = length
		envs = append(envs, envVar)
		// This is the Go equivalent of "environ++" in C.
		environ = (*unsafe.Pointer)(unsafe.Pointer(uintptr(unsafe.Pointer(environ)) + unsafe.Sizeof(environ)))
	}
	return envs
}

// cstring converts a Go string to a C string.
func cstring(s string) []byte {
	data := make([]byte, len(s)+1)
	copy(data, s)
	// final byte should be zero from the initial allocation
	return data
}

func splitSlice(p []byte) (buf *byte, len uintptr) {
	slice := (*sliceHeader)(unsafe.Pointer(&p))
	return slice.buf, slice.len
}

//export strlen
func libc_strlen(ptr unsafe.Pointer) uintptr

// ssize_t write(int fd, const void *buf, size_t count)
//export write
func libc_write(fd int32, buf *byte, count uint) int

// char *getenv(const char *name);
//export getenv
func libc_getenv(name *byte) *byte

// ssize_t read(int fd, void *buf, size_t count);
//export read
func libc_read(fd int32, buf *byte, count uint) int

// int open(const char *pathname, int flags, mode_t mode);
//export open
func libc_open(pathname *byte, flags int32, mode uint32) int32

// int close(int fd)
//export close
func libc_close(fd int32) int32

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
//export mmap
func libc_mmap(addr unsafe.Pointer, length uintptr, prot, flags, fd int32, offset uintptr) unsafe.Pointer

// int mprotect(void *addr, size_t len, int prot);
//export mprotect
func libc_mprotect(addr unsafe.Pointer, len uintptr, prot int32) int32

// int mkdir(const char *pathname, mode_t mode);
//export mkdir
func libc_mkdir(pathname *byte, mode uint32) int32

// int rmdir(const char *pathname);
//export rmdir
func libc_rmdir(pathname *byte) int32

// The odd $INODE64 suffix is an Apple compatibility feature, see https://assert.cc/posts/darwin_use_64_bit_inode_vs_ctypes/
// Without it, you get the old, smaller struct stat from mac os 10.2 or so.

// int stat(const char *path, struct stat * buf);
//export stat$INODE64
func libc_stat(pathname *byte, ptr unsafe.Pointer) int32

// int lstat(const char *path, struct stat * buf);
//export lstat$INODE64
func libc_lstat(pathname *byte, ptr unsafe.Pointer) int32

// int unlink(const char *pathname);
//export unlink
func libc_unlink(pathname *byte) int32

//go:extern environ
var libc_environ *unsafe.Pointer
