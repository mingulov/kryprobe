/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * iochk: deterministic block I/O check for the kcrypto QEMU demo guest.
 *
 * Writes N deterministic bytes (fixed-seed PRNG) to a device or file,
 * fsyncs, reads back, and compares in memory. stdout carries
 * DEMO:IO lines ONLY (metadata: phase, bytes, status, match).
 * Buffer contents are NEVER printed. Exit nonzero on any mismatch:
 * a failed readback must never pass.
 *
 * Usage: iochk --dev PATH --bytes N [--chunk C]
 *
 * Exits: 0 ok, 1 I/O or mismatch failure, 2 usage.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t prng_state;

static uint64_t prng_next(void)
{
	prng_state ^= prng_state >> 12;
	prng_state ^= prng_state << 25;
	prng_state ^= prng_state >> 27;
	return prng_state * 0x2545f4914f6cdd1dull;
}

/* Deterministic stream: byte i depends only on i (restartable). */
static void stream_fill(unsigned char *buf, size_t len, uint64_t base)
{
	size_t i;
	uint64_t word = 0;
	prng_state = base ^ 0x9e3779b97f4a7c15ull;
	if (prng_state == 0)
		prng_state = 1;
	for (i = 0; i < len; i++) {
		if ((i % 8) == 0)
			word = prng_next();
		buf[i] = (unsigned char)(word >> ((i % 8) * 8));
	}
}

static double mono_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char *flag_value(int argc, char **argv, const char *flag)
{
	int i;
	for (i = 0; i < argc - 1; i++) {
		if (strcmp(argv[i], flag) == 0)
			return argv[i + 1];
	}
	return NULL;
}

static void emit(const char *phase, long long bytes, int status,
		 const char *extra)
{
	printf("DEMO:IO {\"phase\": \"%s\", \"bytes\": %lld,"
	       " \"status\": %d%s, \"ts_mono\": %.6f}\n",
	       phase, bytes, status, extra ? extra : "", mono_now());
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *dev = flag_value(argc, argv, "--dev");
	const char *s = flag_value(argc, argv, "--bytes");
	const char *c = flag_value(argc, argv, "--chunk");
	long long total, chunk = 1 << 20, off;
	unsigned char *wbuf = NULL, *rbuf = NULL;
	int fd = -1, rc = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!dev || !s || (total = atoll(s)) <= 0 ||
	    (c && (chunk = atoll(c)) <= 0) || chunk > (1 << 24)) {
		fprintf(stderr, "usage: iochk --dev PATH --bytes N"
			" [--chunk C]\n");
		return 2;
	}
	wbuf = malloc((size_t)chunk);
	rbuf = malloc((size_t)chunk);
	if (!wbuf || !rbuf) {
		fprintf(stderr, "iochk: out of memory\n");
		return 1;
	}
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "iochk: open %s: %s\n", dev,
			strerror(errno));
		emit("open", 0, -errno, NULL);
		goto done;
	}
	for (off = 0; off < total;) {
		long long want = total - off;
		ssize_t n;
		size_t got = 0;
		if (want > chunk)
			want = chunk;
		stream_fill(wbuf, (size_t)want, (uint64_t)off);
		while (got < (size_t)want) {
			n = write(fd, wbuf + got, (size_t)want - got);
			if (n <= 0) {
				fprintf(stderr, "iochk: write at %lld: %s\n",
					off, strerror(errno));
				emit("write", off, -errno, NULL);
				goto done;
			}
			got += (size_t)n;
		}
		off += want;
	}
	emit("write", total, 0, NULL);
	if (fsync(fd) != 0) {
		fprintf(stderr, "iochk: fsync: %s\n", strerror(errno));
		emit("fsync", total, -errno, NULL);
		goto done;
	}
	emit("fsync", total, 0, NULL);
	if (lseek(fd, 0, SEEK_SET) != 0) {
		fprintf(stderr, "iochk: seek: %s\n", strerror(errno));
		emit("read", 0, -errno, NULL);
		goto done;
	}
	for (off = 0; off < total;) {
		long long want = total - off;
		ssize_t n;
		size_t got = 0;
		if (want > chunk)
			want = chunk;
		while (got < (size_t)want) {
			n = read(fd, rbuf + got, (size_t)want - got);
			if (n <= 0) {
				fprintf(stderr, "iochk: read at %lld: %s\n",
					off, n == 0 ? "short" :
					strerror(errno));
				emit("read", off, n == 0 ? -EIO : -errno,
				     NULL);
				goto done;
			}
			got += (size_t)n;
		}
		stream_fill(wbuf, (size_t)want, (uint64_t)off);
		if (memcmp(wbuf, rbuf, (size_t)want) != 0) {
			fprintf(stderr, "iochk: mismatch at %lld\n", off);
			emit("verify", off, -EIO,
			     ", \"match\": false");
			goto done;
		}
		off += want;
	}
	emit("read", total, 0, NULL);
	emit("verify", total, 0, ", \"match\": true");
	rc = 0;
done:
	if (fd >= 0)
		close(fd);
	free(wbuf);
	free(rbuf);
	return rc;
}
