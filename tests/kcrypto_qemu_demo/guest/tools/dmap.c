/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * dmap: minimal device-mapper control for the kcrypto QEMU demo guest.
 *
 * Static build, dm-ioctl only (no libdevmapper, no cryptsetup).
 * stdout carries DEMO:DMAP lines ONLY (metadata: event, name,
 * status, sectors, open count). The target table (cipher + key +
 * device) is read from a file and NEVER printed, traced, or taken
 * from argv. stderr carries stage + errno only.
 *
 * Subcommands:
 *   dmap create --name N
 *   dmap load --name N --table-file F --sectors S
 *   dmap resume --name N
 *   dmap remove --name N
 *   dmap status --name N
 *
 * Exits: 0 ok, 1 ioctl failure, 2 usage.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include <linux/dm-ioctl.h>

#define DM_BUF_SIZE (16 * 1024)

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

static void emit(const char *event, const char *name, long sectors, int status)
{
	printf("DEMO:DMAP {\"event\": \"%s\", \"name\": \"", event);
	json_escape(stdout, name);
	printf("\", \"sectors\": %ld, \"status\": %d, \"ts_mono\": %.6f}\n",
	       sectors, status, mono_now());
	fflush(stdout);
}

static int dm_open(void)
{
	int fd = open("/dev/mapper/control", O_RDWR);
	if (fd < 0)
		fprintf(stderr, "dmap: open /dev/mapper/control: %s\n",
			strerror(errno));
	return fd;
}

static void dm_init(struct dm_ioctl *dmi, const char *name)
{
	memset(dmi, 0, sizeof(*dmi) + DM_BUF_SIZE);
	dmi->version[0] = DM_VERSION_MAJOR;
	dmi->version[1] = DM_VERSION_MINOR;
	dmi->version[2] = DM_VERSION_PATCHLEVEL;
	dmi->data_size = sizeof(*dmi) + DM_BUF_SIZE;
	dmi->data_start = sizeof(*dmi);
	if (name)
		strncpy(dmi->name, name, sizeof(dmi->name) - 1);
}

static int cmd_create(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	static unsigned char buf[sizeof(struct dm_ioctl) + DM_BUF_SIZE];
	struct dm_ioctl *dmi = (struct dm_ioctl *)buf;
	int fd, rc;

	if (!name) {
		fprintf(stderr, "usage: dmap create --name N\n");
		return 2;
	}
	fd = dm_open();
	if (fd < 0)
		return 1;
	dm_init(dmi, name);
	rc = ioctl(fd, DM_DEV_CREATE, dmi);
	if (rc != 0) {
		fprintf(stderr, "dmap: create: %s\n", strerror(errno));
		emit("create", name, -1, -errno);
		close(fd);
		return 1;
	}
	emit("create", name, -1, 0);
	close(fd);
	return 0;
}

static int cmd_load(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	const char *table_file = flag_value(argc, argv, "--table-file");
	const char *s = flag_value(argc, argv, "--sectors");
	static unsigned char buf[sizeof(struct dm_ioctl) + DM_BUF_SIZE];
	struct dm_ioctl *dmi = (struct dm_ioctl *)buf;
	struct dm_target_spec *tgt;
	char *params;
	FILE *fp;
	char table[4096];
	size_t len;
	int fd, rc;
	long sectors;

	if (!name || !table_file || !s || (sectors = atol(s)) <= 0) {
		fprintf(stderr,
			"usage: dmap load --name N --table-file F --sectors S\n");
		return 2;
	}
	fp = fopen(table_file, "r");
	if (!fp) {
		fprintf(stderr, "dmap: load: open table: %s\n",
			strerror(errno));
		return 1;
	}
	if (!fgets(table, sizeof(table), fp)) {
		fprintf(stderr, "dmap: load: read table: %s\n",
			strerror(errno));
		fclose(fp);
		return 1;
	}
	fclose(fp);
	table[strcspn(table, "\r\n")] = '\0';
	len = strlen(table) + 1;
	fd = dm_open();
	if (fd < 0)
		return 1;
	dm_init(dmi, name);
	dmi->target_count = 1;
	tgt = (struct dm_target_spec *)(buf + sizeof(*dmi));
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = (uint64_t)sectors;
	/* Target type is the third whitespace field of the table line. */
	{
		char *p = table, *q;
		int field = 0;
		while (field < 2 && (q = strchr(p, ' ')) != NULL) {
			p = q + 1;
			field++;
		}
		q = strchr(p, ' ');
		if (field != 2 || !q || (size_t)(q - p) >= sizeof(tgt->target_type)) {
			fprintf(stderr, "dmap: load: malformed table"
				" (want '<start> <len> <type> ...')\n");
			close(fd);
			return 1;
		}
		memcpy(tgt->target_type, p, (size_t)(q - p));
		tgt->target_type[q - p] = '\0';
		tgt->next = (uint32_t)(sizeof(*tgt) + len);
		params = (char *)(tgt + 1);
		/* Params are everything after '<start> <len> <type> '. */
		memcpy(params, q + 1, strlen(q + 1) + 1);
	}
	rc = ioctl(fd, DM_TABLE_LOAD, dmi);
	if (rc != 0) {
		fprintf(stderr, "dmap: load: %s\n", strerror(errno));
		emit("load", name, sectors, -errno);
		close(fd);
		return 1;
	}
	emit("load", name, sectors, 0);
	close(fd);
	return 0;
}

static int cmd_simple(const char *event, unsigned long cmd, int argc,
		      char **argv, const char *usage)
{
	const char *name = flag_value(argc, argv, "--name");
	static unsigned char buf[sizeof(struct dm_ioctl) + DM_BUF_SIZE];
	struct dm_ioctl *dmi = (struct dm_ioctl *)buf;
	int fd, rc;

	if (!name) {
		fprintf(stderr, "usage: %s\n", usage);
		return 2;
	}
	fd = dm_open();
	if (fd < 0)
		return 1;
	dm_init(dmi, name);
	rc = ioctl(fd, cmd, dmi);
	if (rc != 0) {
		fprintf(stderr, "dmap: %s: %s\n", event, strerror(errno));
		emit(event, name, -1, -errno);
		close(fd);
		return 1;
	}
	emit(event, name, (long)dmi->open_count, 0);
	close(fd);
	return 0;
}

static int cmd_status(int argc, char **argv)
{
	const char *name = flag_value(argc, argv, "--name");
	static unsigned char buf[sizeof(struct dm_ioctl) + DM_BUF_SIZE];
	struct dm_ioctl *dmi = (struct dm_ioctl *)buf;
	int fd, rc;

	if (!name) {
		fprintf(stderr, "usage: dmap status --name N\n");
		return 2;
	}
	fd = dm_open();
	if (fd < 0)
		return 1;
	dm_init(dmi, name);
	rc = ioctl(fd, DM_DEV_STATUS, dmi);
	if (rc != 0) {
		fprintf(stderr, "dmap: status: %s\n", strerror(errno));
		emit("status", name, -1, -errno);
		close(fd);
		return 1;
	}
	printf("DEMO:DMAP {\"event\": \"status\", \"name\": \"");
	json_escape(stdout, name);
	printf("\", \"open_count\": %u, \"live\": %s, \"status\": 0,"
	       " \"ts_mono\": %.6f}\n", dmi->open_count,
	       (dmi->flags & DM_SUSPEND_FLAG) ? "false" : "true", mono_now());
	fflush(stdout);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) {
		fprintf(stderr, "usage: dmap"
			" {create|load|resume|remove|status} ...\n");
		return 2;
	}
	if (strcmp(argv[1], "create") == 0)
		return cmd_create(argc - 1, argv + 1);
	if (strcmp(argv[1], "load") == 0)
		return cmd_load(argc - 1, argv + 1);
	if (strcmp(argv[1], "resume") == 0)
		return cmd_simple("resume", DM_DEV_SUSPEND, argc - 1, argv + 1,
				  "dmap resume --name N");
	if (strcmp(argv[1], "remove") == 0)
		return cmd_simple("remove", DM_DEV_REMOVE, argc - 1, argv + 1,
				  "dmap remove --name N");
	if (strcmp(argv[1], "status") == 0)
		return cmd_status(argc - 1, argv + 1);
	fprintf(stderr, "usage: dmap {create|load|resume|remove|status} ...\n");
	return 2;
}
