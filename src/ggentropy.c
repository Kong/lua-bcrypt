/*
 * ggentropy v1.0
 *
 * Copyright (c) 2021 Michael Savage <mike@mikejsavage.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined( _WIN32 )
#  define PLATFORM_WINDOWS 1

#elif defined( __linux__ )
#  define PLATFORM_LINUX 1

#elif defined( __APPLE__ )
#  define PLATFORM_HAS_ARC4RANDOM 1

#elif defined( __FreeBSD__ ) || defined( __OpenBSD__ ) || defined( __NetBSD__ )
#  define PLATFORM_HAS_ARC4RANDOM 1

#else
#  error new platform
#endif

#include <stdbool.h>
#include <stddef.h>
#include <assert.h>

#if PLATFORM_WINDOWS

#pragma comment( lib, "bcrypt.lib" )

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

bool ggentropy( void * buf, size_t n ) {
	assert( n <= 256 );
	return !FAILED( BCryptGenRandom( NULL, ( PUCHAR ) buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG ) );
}

#elif PLATFORM_LINUX

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>

#ifdef SYS_getrandom
static int getentropy_getrandom(void *buf, size_t len);
#endif
static int getentropy_urandom(void *buf, size_t len);
#ifdef SYS__sysctl
static int getentropy_sysctl(void *buf, size_t len);
#endif

bool ggentropy( void * buf, size_t n ) {
	assert( n <= 256 );
	int ret;

#ifdef SYS_getrandom
	static bool getrandom_available = true;

	if (getrandom_available) {
		/*
		 * Try descriptor-less getrandom()
		 */
		ret = getentropy_getrandom(buf, n);
		if (ret != -1)
			return true;

		if (errno == ENOSYS) {
			getrandom_available = false;
		}
		else {
			return false;
		}
	}
#endif

	/*
	 * Try to get entropy with /dev/urandom
	 *
	 * This can fail if the process is inside a chroot or if file
	 * descriptors are exhausted.
	 */
	ret = getentropy_urandom(buf, n);
	if (ret != -1)
		return true;

#ifdef SYS__sysctl
	/*
	 * Try to use sysctl CTL_KERN, KERN_RANDOM, RANDOM_UUID.
	 * sysctl is a failsafe API, so it guarantees a result.  This
	 * should work inside a chroot, or when file descriptors are
	 * exhuasted.
	 *
	 * However this can fail if the Linux kernel removes support
	 * for sysctl.  Starting in 2007, there have been efforts to
	 * deprecate the sysctl API/ABI, and push callers towards use
	 * of the chroot-unavailable fd-using /proc mechanism --
	 * essentially the same problems as /dev/urandom.
	 *
	 * Numerous setbacks have been encountered in their deprecation
	 * schedule, so as of June 2014 the kernel ABI still exists on
	 * most Linux architectures. The sysctl() stub in libc is missing
	 * on some systems.  There are also reports that some kernels
	 * spew messages to the console.
	 */
	ret = getentropy_sysctl(buf, n);
	if (ret != -1)
		return true;
#endif /* SYS__sysctl */

	return false;
}

#ifdef SYS_getrandom
static int
getentropy_getrandom(void *buf, size_t len)
{
	int pre_errno = errno;
	int ret;
	unsigned char *p = buf;
	int left = len;

	while (left > 0) {
		ret = syscall(SYS_getrandom, p, left, 0);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		left -= ret;
		p += ret;
	}

	errno = pre_errno;
	return (0);
}
#endif

static int
getentropy_urandom(void *buf, size_t len)
{
	struct stat st;
	size_t i;
	int fd, cnt, flags;
	int save_errno = errno;

start:

	flags = O_RDONLY;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
	fd = open("/dev/urandom", flags, 0);
	if (fd == -1) {
		if (errno == EINTR)
			goto start;
		goto nodevrandom;
	}
#ifndef O_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

	/* Lightly verify that the device node looks sane */
	if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)) {
		close(fd);
		goto nodevrandom;
	}
	if (ioctl(fd, RNDGETENTCNT, &cnt) == -1) {
		close(fd);
		goto nodevrandom;
	}
	for (i = 0; i < len; ) {
		size_t wanted = len - i;
		ssize_t ret = read(fd, (char *)buf + i, wanted);

		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			close(fd);
			goto nodevrandom;
		}
		i += ret;
	}
	close(fd);

	errno = save_errno;
	return 0;

nodevrandom:
	errno = EIO;
	return -1;
}

#ifdef SYS__sysctl
static int
getentropy_sysctl(void *buf, size_t len)
{
	static int mib[] = { CTL_KERN, KERN_RANDOM, RANDOM_UUID };
	size_t i;
	int save_errno = errno;

	for (i = 0; i < len; ) {
		size_t chunk = min(len - i, 16);

		/* SYS__sysctl because some systems already removed sysctl() */
		struct __sysctl_args args = {
			.name = mib,
			.nlen = 3,
			.oldval = (char *)buf + i,
			.oldlenp = &chunk,
		};
		if (syscall(SYS__sysctl, &args) != 0)
			goto sysctlfailed;
		i += chunk;
	}

	errno = save_errno;
	return 0;
sysctlfailed:
	errno = EIO;
	return -1;
}
#endif /* SYS__sysctl */

#elif PLATFORM_HAS_ARC4RANDOM

#include <stdlib.h>

bool ggentropy( void * buf, size_t n ) {
	assert( n <= 256 );
	arc4random_buf( buf, n );
	return true;
}

#else
#error new platform
#endif
