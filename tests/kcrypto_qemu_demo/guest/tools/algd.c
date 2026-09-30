/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * algd: AF_ALG skcipher workload for the kcrypto QEMU demo guest.
 *
 * Static build, standard syscalls only. Mirrors the choreography of
 * the committed Rust AF_ALG fixture (bind skcipher/name, ALG_SET_KEY,
 * accept, one sendmsg + full read per op) with exact performed
 * counts. stdout carries DEMO:* marker lines ONLY (metadata: seq,
 * op, bytes, status, alloc id, monotonic timestamps). Keys, IVs and
 * payload bytes are generated in-process from a fixed-seed PRNG and
 * NEVER printed, traced, or taken from argv.
 *
 * Subcommands:
 *   algd registry
 *     dump /proc/crypto as DEMO:REGISTRY lines (name/driver/
 *     priority/type only).
 *   algd run --name N --keylen K --ops O --bytes B --rate R
 *        --op encrypt|decrypt --alloc-id A
 *     one allocation, O paced ops of B bytes each; one DEMO:LEDGER
 *     row per performed op. Aborts (exit 1) on the first failing
 *     op: a short ledger must never pass.
 *   algd hold --name N --keylen K --hold-s S --alloc-id A
 *     allocate + setkey, emit DEMO:HANDLE held, sleep S, emit
 *     released. The retained-handle control for D02.
 *   algd probe --name N --keylen K
 *     bind + setkey + accept + close without I/O; emits one
 *     DEMO:PROBE bind-probe row (no LEDGER pollution).
 *
 * Exits: 0 ok, 1 internal/operation failure, 2 usage.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_alg.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Fixed-seed PRNG: public deterministic test bytes (never output). */
static uint64_t prng_state = 0x243f6a8885a308d3ull;

static uint64_t prng_next(void)
{
	prng_state ^= prng_state >> 12;
	prng_state ^= prng_state << 25;
	prng_state ^= prng_state >> 27;
	return prng_state * 0x2545f4914f6cdd1dull;
}

static void prng_fill(unsigned char *buf, size_t len, uint64_t seed)
{
	size_t i;
	uint64_t word = 0;
	prng_state = seed ^ 0x243f6a8885a308d3ull;
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

/* sockaddr_alg: family u16 + type[14] + feat/mask u32 + name[64]. */
static int alg_bind(const char *type, const char *name)
{
	unsigned char addr[88];
	int fd, rc;
	memset(addr, 0, sizeof(addr));
	addr[0] = (unsigned char)(AF_ALG & 0xff);
	addr[1] = (unsigned char)((AF_ALG >> 8) & 0xff);
	strncpy((char *)addr + 2, type, 13);
	strncpy((char *)addr + 2 + 14 + 8, name, 63);
	fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return -1;
	rc = bind(fd, (struct sockaddr *)addr, sizeof(addr));
	if (rc != 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

static int alg_setkey(int fd, const unsigned char *key, size_t keylen)
{
	return setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, (socklen_t)keylen);
}

/* One skcipher op: sendmsg(op + iv cmsg, plaintext) + full read. */
static int alg_crypt(int opfd, int encrypt, const unsigned char *in,
		     unsigned char *out, size_t len, const unsigned char *iv,
		     size_t ivlen)
{
	unsigned char cbuf[CMSG_SPACE(sizeof(uint32_t)) +
			   CMSG_SPACE(sizeof(struct af_alg_iv) + 64)];
	struct af_alg_iv *alg_iv;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;
	size_t got = 0;
	uint32_t *op;

	memset(cbuf, 0, sizeof(cbuf));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)in;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	op = (uint32_t *)CMSG_DATA(cmsg);
	*op = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
	alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	alg_iv->ivlen = (uint32_t)ivlen;
	memcpy(alg_iv->iv, iv, ivlen);
	/* Exact control length: trailing zero bytes parse as an
	 * invalid cmsg and fail the op with EINVAL. */
	msg.msg_controllen = CMSG_SPACE(sizeof(uint32_t)) +
			     CMSG_SPACE(sizeof(struct af_alg_iv) + ivlen);

	n = sendmsg(opfd, &msg, 0);
	if (n < 0)
		return -errno;
	if ((size_t)n != len)
		return -EIO;
	while (got < len) {
		n = read(opfd, out + got, len - got);
		if (n < 0)
			return -errno;
		if (n == 0)
			return -EIO;
		got += (size_t)n;
	}
	return 0;
}

static void json_escape(FILE *out, const char *s)
{
	for (; *s; s++) {
		if (*s == '"' || *s == '\\')
			fprintf(out, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			fprintf(out, "\\u%04x", *s);
		else
			fputc(*s, out);
	}
}

static int cmd_registry(void)
{
	FILE *fp = fopen("/proc/crypto", "r");
	char line[256];
	char name[128] = "", driver[128] = "", type[64] = "";
	long priority = -1;
	int in_block = 0;

	if (!fp) {
		fprintf(stderr, "algd: registry: open /proc/crypto: %s\n",
			strerror(errno));
		return 1;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '\n' || line[0] == '\r') {
			if (in_block && name[0]) {
				printf("DEMO:REGISTRY {\"name\": \"");
				json_escape(stdout, name);
				printf("\", \"driver\": \"");
				json_escape(stdout, driver);
				printf("\", \"priority\": %ld, \"type\": \"",
				       priority);
				json_escape(stdout, type);
				printf("\"}\n");
			}
			name[0] = driver[0] = type[0] = '\0';
			priority = -1;
			in_block = 0;
			continue;
		}
		in_block = 1;
		if (strncmp(line, "name", 4) == 0)
			sscanf(line, "name : %127s", name);
		else if (strncmp(line, "driver", 6) == 0)
			sscanf(line, "driver : %127s", driver);
		else if (strncmp(line, "priority", 8) == 0)
			sscanf(line, "priority : %ld", &priority);
		else if (strncmp(line, "type", 4) == 0)
			sscanf(line, "type : %63s", type);
	}
	fclose(fp);
	return 0;
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

static int cmd_run(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	const char *opname = flag_value(argc, argv, "--op");
	const char *alloc_id = flag_value(argc, argv, "--alloc-id");
	const char *s;
	long keylen, ops, bytes, rate;
	int tfmfd = -1, opfd = -1, encrypt, rc = 1, i;
	unsigned char *key = NULL, *plain = NULL, *out = NULL, *iv = NULL;

	if (!name || !opname || !alloc_id ||
	    !(s = flag_value(argc, argv, "--keylen")) || (keylen = atol(s)) <= 0 ||
	    !(s = flag_value(argc, argv, "--ops")) || (ops = atol(s)) <= 0 ||
	    !(s = flag_value(argc, argv, "--bytes")) || (bytes = atol(s)) <= 0 ||
	    !(s = flag_value(argc, argv, "--rate")) || (rate = atol(s)) <= 0) {
		fprintf(stderr, "usage: algd run --name N --keylen K --ops O"
			" --bytes B --rate R --op encrypt|decrypt"
			" --alloc-id A\n");
		return 2;
	}
	if (strcmp(opname, "encrypt") == 0)
		encrypt = 1;
	else if (strcmp(opname, "decrypt") == 0)
		encrypt = 0;
	else {
		fprintf(stderr, "algd: run: op must be encrypt|decrypt\n");
		return 2;
	}
	if (keylen > 64 || bytes > (1 << 20)) {
		fprintf(stderr, "algd: run: keylen/bytes out of range\n");
		return 2;
	}
	key = malloc((size_t)keylen);
	plain = malloc((size_t)bytes);
	out = malloc((size_t)bytes);
	iv = malloc(64);
	if (!key || !plain || !out || !iv) {
		fprintf(stderr, "algd: run: out of memory\n");
		rc = 1;
		goto done;
	}
	prng_fill(key, (size_t)keylen, 0xbeef);
	tfmfd = alg_bind("skcipher", name);
	if (tfmfd < 0) {
		fprintf(stderr, "algd: run: bind %s: %s\n", name,
			strerror(errno));
		goto done;
	}
	if (alg_setkey(tfmfd, key, (size_t)keylen) != 0) {
		fprintf(stderr, "algd: run: setkey: %s\n", strerror(errno));
		goto done;
	}
	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		fprintf(stderr, "algd: run: accept: %s\n", strerror(errno));
		goto done;
	}
	for (i = 0; i < ops; i++) {
		struct timespec gap;
		int op_status;
		prng_fill(plain, (size_t)bytes, 0x1000 + (uint64_t)i);
		prng_fill(iv, 16, 0x2000 + (uint64_t)i);
		op_status = alg_crypt(opfd, encrypt, plain, out, (size_t)bytes,
				      iv, 16);
		if (op_status != 0) {
			printf("DEMO:LEDGER {\"seq\": %d, \"op\": \"%s\","
			       " \"bytes\": %ld, \"status\": %d,"
			       " \"alloc_id\": \"", i, opname, bytes,
			       op_status);
			json_escape(stdout, alloc_id);
			printf("\", \"name\": \"");
			json_escape(stdout, name);
			printf("\", \"ts_mono\": %.6f}\n", mono_now());
			fflush(stdout);
			fprintf(stderr, "algd: run: op %d failed, aborting\n",
				i);
			goto done;
		}
		printf("DEMO:LEDGER {\"seq\": %d, \"op\": \"%s\","
		       " \"bytes\": %ld, \"status\": 0, \"alloc_id\": \"",
		       i, opname, bytes);
		json_escape(stdout, alloc_id);
		printf("\", \"name\": \"");
		json_escape(stdout, name);
		printf("\", \"ts_mono\": %.6f}\n", mono_now());
		fflush(stdout);
		gap.tv_sec = 0;
		gap.tv_nsec = 1000000000L / rate;
		nanosleep(&gap, NULL);
	}
	rc = 0;
done:
	if (opfd >= 0)
		close(opfd);
	if (tfmfd >= 0)
		close(tfmfd);
	free(key);
	free(plain);
	free(out);
	free(iv);
	return rc;
}

static int cmd_hold(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	const char *alloc_id = flag_value(argc, argv, "--alloc-id");
	const char *s = flag_value(argc, argv, "--hold-s");
	const char *k = flag_value(argc, argv, "--keylen");
	long hold_s, keylen;
	int tfmfd = -1, opfd = -1, rc = 1;
	unsigned char *key = NULL;

	if (!name || !alloc_id || !s || (hold_s = atol(s)) <= 0 ||
	    !k || (keylen = atol(k)) <= 0 || keylen > 64) {
		fprintf(stderr, "usage: algd hold --name N --keylen K"
			" --hold-s S --alloc-id A\n");
		return 2;
	}
	key = malloc((size_t)keylen);
	if (!key) {
		fprintf(stderr, "algd: hold: out of memory\n");
		return 1;
	}
	prng_fill(key, (size_t)keylen, 0xbeef);
	tfmfd = alg_bind("skcipher", name);
	if (tfmfd < 0) {
		fprintf(stderr, "algd: hold: bind %s: %s\n", name,
			strerror(errno));
		goto done;
	}
	if (alg_setkey(tfmfd, key, (size_t)keylen) != 0) {
		fprintf(stderr, "algd: hold: setkey: %s\n", strerror(errno));
		goto done;
	}
	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		fprintf(stderr, "algd: hold: accept: %s\n", strerror(errno));
		goto done;
	}
	printf("DEMO:HANDLE {\"event\": \"held\", \"alloc_id\": \"");
	json_escape(stdout, alloc_id);
	printf("\", \"name\": \"");
	json_escape(stdout, name);
	printf("\", \"ts_mono\": %.6f}\n", mono_now());
	fflush(stdout);
	sleep((unsigned int)hold_s);
	printf("DEMO:HANDLE {\"event\": \"released\", \"alloc_id\": \"");
	json_escape(stdout, alloc_id);
	printf("\", \"name\": \"");
	json_escape(stdout, name);
	printf("\", \"ts_mono\": %.6f}\n", mono_now());
	fflush(stdout);
	rc = 0;
done:
	if (opfd >= 0)
		close(opfd);
	if (tfmfd >= 0)
		close(tfmfd);
	free(key);
	return rc;
}

static int cmd_probe(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	const char *k = flag_value(argc, argv, "--keylen");
	long keylen;
	int tfmfd = -1, opfd = -1, rc = 1;
	unsigned char *key = NULL;

	if (!name || !k || (keylen = atol(k)) <= 0 || keylen > 64) {
		fprintf(stderr, "usage: algd probe --name N --keylen K\n");
		return 2;
	}
	key = malloc((size_t)keylen);
	if (!key) {
		fprintf(stderr, "algd: probe: out of memory\n");
		return 1;
	}
	prng_fill(key, (size_t)keylen, 0xbeef);
	tfmfd = alg_bind("skcipher", name);
	if (tfmfd < 0)
		goto out;
	if (alg_setkey(tfmfd, key, (size_t)keylen) != 0)
		goto out;
	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0)
		goto out;
	rc = 0;
out:
	printf("DEMO:PROBE {\"fact\": \"bind-probe\", \"name\": \"");
	json_escape(stdout, name);
	printf("\", \"ok\": %s, \"ts_mono\": %.6f}\n",
	       rc == 0 ? "true" : "false", mono_now());
	fflush(stdout);
	if (opfd >= 0)
		close(opfd);
	if (tfmfd >= 0)
		close(tfmfd);
	free(key);
	return rc;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) {
		fprintf(stderr, "usage: algd {registry|run|hold|probe} ...\n");
		return 2;
	}
	if (strcmp(argv[1], "registry") == 0)
		return cmd_registry();
	if (strcmp(argv[1], "run") == 0)
		return cmd_run(argc - 1, argv + 1);
	if (strcmp(argv[1], "hold") == 0)
		return cmd_hold(argc - 1, argv + 1);
	if (strcmp(argv[1], "probe") == 0)
		return cmd_probe(argc - 1, argv + 1);
	fprintf(stderr, "usage: algd {registry|run|hold|probe} ...\n");
	return 2;
}
