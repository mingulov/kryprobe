// SPDX-License-Identifier: GPL-2.0-only
/*
 * kcrypto_fixture provider: test-only skcipher drivers (sync, async,
 * failing-init) plus a minimal sync AEAD driver (config-shape only,
 * no tag semantics until T10), the JSONL ledger ring and debugfs
 * control (see fixture.h, README.md).
 *
 * TEST ONLY. The "cipher" is XOR with the key byte. It provides no
 * confidentiality. Never install on a production host.
 */
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <crypto/skcipher.h>

#include "fixture.h"

static char *run_suffix = "dev";
module_param(run_suffix, charp, 0444);
MODULE_PARM_DESC(run_suffix, "per-run driver-name suffix ([A-Za-z0-9_-], 1-32 chars)");

/* ------------------------------------------------------------------ */
/* ledger ring                                                         */
/* ------------------------------------------------------------------ */

struct kxc_ledger {
	char (*rows)[KXC_ROW_LEN];
	u16 lens[KXC_ROWS_MAX];
	atomic_t count;
	atomic64_t dropped;
	spinlock_t lock;
};

static struct kxc_ledger kxc_log;

int kxc_ledger_emit(const char *fmt, ...)
{
	va_list args;
	char tmp[KXC_ROW_LEN];
	int len, idx;

	va_start(args, fmt);
	len = vsnprintf(tmp, sizeof(tmp), fmt, args);
	va_end(args);
	if (len < 0)
		return -EINVAL;
	if (len >= (int)sizeof(tmp))
		return -E2BIG;

	spin_lock_bh(&kxc_log.lock);
	idx = atomic_read(&kxc_log.count);
	if (idx < KXC_ROWS_MAX) {
		memcpy(kxc_log.rows[idx], tmp, len);
		kxc_log.lens[idx] = (u16)len;
		atomic_set(&kxc_log.count, idx + 1);
		spin_unlock_bh(&kxc_log.lock);
		return 0;
	}
	atomic64_inc(&kxc_log.dropped);
	spin_unlock_bh(&kxc_log.lock);
	return -ENOSPC;
}

u64 kxc_ledger_dropped(void)
{
	return (u64)atomic64_read(&kxc_log.dropped);
}

void kxc_ledger_reset(void)
{
	spin_lock_bh(&kxc_log.lock);
	atomic_set(&kxc_log.count, 0);
	atomic64_set(&kxc_log.dropped, 0);
	spin_unlock_bh(&kxc_log.lock);
}

/* ------------------------------------------------------------------ */
/* run state                                                           */
/* ------------------------------------------------------------------ */

static struct kxc_run kxc_run;
static DEFINE_MUTEX(kxc_run_lock);
/*
 * Orders STOP against PREPARE: STOP's idle-check+set and
 * PREPARE's flag-clear+begin are mutually exclusive under
 * kxc_stop_lock, so a STOP can never arm a run it did not
 * observe. GO never takes this lock, so STOP still interrupts
 * a running scenario.
 */
static DEFINE_MUTEX(kxc_stop_lock);

/*
 * Provider-body entry marker (P3r): counts kxc_do_crypt entries since
 * PREPARE (reset in kxc_run_begin). Incremented FIRST on body entry —
 * entry means entry, including the keyless early return. Read by the
 * return rows + done trailer as independent truth: a refused op with
 * an unchanged marker never entered the provider, which errno alone
 * cannot prove (the body itself returns -ENOKEY when keyless).
 * Skcipher only; the AEAD body is out of T08 scope.
 */
static atomic64_t kxc_crypt_entries;

u64 kxc_next_seq(struct kxc_run *run)
{
	return (u64)atomic64_inc_return(&run->seq);
}

static bool kxc_token_ok(const char *s, size_t max)
{
	size_t i;

	if (!s || !s[0])
		return false;
	for (i = 0; s[i] && i < max; i++) {
		char c = s[i];

		if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') &&
		    (c < '0' || c > '9') && c != '-' && c != '_')
			return false;
	}
	return s[i] == '\0';
}

int kxc_run_begin(struct kxc_run *run, const char *id,
		  const char *scenario, u64 seed)
{
	if (!kxc_token_ok(id, KXC_RUN_ID_MAX) ||
	    !kxc_token_ok(scenario, KXC_SCENARIO_MAX))
		return -EINVAL;
	strscpy(run->id, id, sizeof(run->id));
	strscpy(run->scenario, scenario, sizeof(run->scenario));
	run->seed = seed;
	atomic64_set(&run->seq, 0);
	/* WRITE_ONCE: STOP observes prepared/done across locks. */
	WRITE_ONCE(run->prepared, true);
	WRITE_ONCE(run->done, false);
	run->fixture_result = 0;
	/* WRITE_ONCE: STOP may store concurrently under kxc_stop_lock. */
	WRITE_ONCE(run->stop, false);
	kxc_ledger_reset();
	atomic64_set(&kxc_crypt_entries, 0);
	return 0;
}

void kxc_run_finish(struct kxc_run *run, int result)
{
	run->fixture_result = result;
	/* WRITE_ONCE: STOP observes done across locks. */
	WRITE_ONCE(run->done, true);
}

bool kxc_run_stop_requested(struct kxc_run *run)
{
	return READ_ONCE(run->stop);
}

void kxc_run_request_stop(struct kxc_run *run)
{
	WRITE_ONCE(run->stop, true);
}

/* ------------------------------------------------------------------ */
/* skcipher drivers (XOR test cipher)                                  */
/* ------------------------------------------------------------------ */

struct kxc_ctx {
	u8 key[32];
	unsigned int keylen;
};

static char kxc_sync_name[KXC_DRV_NAME_MAX];
static char kxc_async_name[KXC_DRV_NAME_MAX];
static char kxc_fail_name[KXC_DRV_NAME_MAX];
static char kxc_aead_name[KXC_DRV_NAME_MAX];

const char *kxc_sync_driver_name(void)
{
	return kxc_sync_name;
}

const char *kxc_async_driver_name(void)
{
	return kxc_async_name;
}

const char *kxc_fail_driver_name(void)
{
	return kxc_fail_name;
}

const char *kxc_aead_driver_name(void)
{
	return kxc_aead_name;
}

static int kxc_cra_init(struct crypto_tfm *tfm)
{
	struct kxc_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

static void kxc_cra_exit(struct crypto_tfm *tfm)
{
	struct kxc_ctx *ctx = crypto_tfm_ctx(tfm);

	memzero_explicit(ctx, sizeof(*ctx));
}

static int kxc_setkey(struct crypto_skcipher *tfm, const u8 *key,
		      unsigned int keylen)
{
	struct kxc_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (keylen < 16 || keylen > sizeof(ctx->key))
		return -EINVAL;
	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;
	return 0;
}

u64 kxc_crypt_entries_count(void)
{
	return (u64)atomic64_read(&kxc_crypt_entries);
}

static int kxc_do_crypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct kxc_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int i;
	int err;

	atomic64_inc(&kxc_crypt_entries);
	if (!ctx->keylen)
		return -ENOKEY;
	{
		u8 *dst;
		const u8 *src;

		err = skcipher_walk_virt(&walk, req, false);
		while (walk.nbytes) {
			dst = walk.dst.virt.addr;
			src = walk.src.virt.addr;
			for (i = 0; i < walk.nbytes; i++)
				dst[i] = src[i] ^ ctx->key[i % ctx->keylen];
			err = skcipher_walk_done(&walk, 0);
		}
	}
	return err;
}

static int kxc_sync_crypt(struct skcipher_request *req)
{
	return kxc_do_crypt(req);
}

/*
 * Genuine crypto backlog: depth-1 driver queue. The first queued
 * submit returns -EINPROGRESS; further concurrent submits with
 * MAY_BACKLOG return -EBUSY and still complete via callback.
 * The hold flag pauses drain queueing so the burst scenario's
 * submit window is fully deterministic (no timing races).
 */
#define KXC_BQ_MAX_QLEN 1
static struct crypto_queue kxc_bq;
/*
 * The crypto_queue API is caller-synchronized (no internal lock):
 * this lock serializes submitters against the drain worker.
 */
static DEFINE_SPINLOCK(kxc_bq_lock);
static struct work_struct kxc_drain_work;
static atomic_t kxc_submit_hold;
static atomic_t kxc_delay_ms;
/*
 * P4r2 one-shot inline completion: when set, the NEXT async submit
 * completes synchronously inside the submit call (crypt + complete
 * before the -EINPROGRESS return) instead of queueing. The
 * scenario consumes it exactly once (cmpxchg); every exit path
 * clears it, so a failed submit cannot arm a later scenario.
 * Forced callback-before-return ordering, deterministic by
 * construction (same thread — no worker race to win or lose).
 */
static atomic_t kxc_inline_once;

static void kxc_async_fn(struct work_struct *work)
{
	struct crypto_async_request *areq, *backlog;
	struct skcipher_request *req;
	int delay_ms, err;

	for (;;) {
		spin_lock_bh(&kxc_bq_lock);
		/*
		 * T09 cryptd-worker shape (crypto/cryptd.c
		 * cryptd_queue_worker, byte-identical 7.0.14/7.2.6):
		 * sample the backlog BEFORE dequeuing, then
		 * progress-notify it before completing the head.
		 * With the depth-1 held queue the burst order is
		 * deterministic: P1,T0,P2,T1,P3,T2,T3.
		 */
		backlog = crypto_get_backlog(&kxc_bq);
		areq = crypto_dequeue_request(&kxc_bq);
		spin_unlock_bh(&kxc_bq_lock);
		if (!areq)
			break;
		if (backlog)
			crypto_request_complete(backlog, -EINPROGRESS);
		delay_ms = atomic_read(&kxc_delay_ms);
		if (delay_ms > 0)
			msleep((unsigned int)delay_ms);
		req = skcipher_request_cast(areq);
		err = kxc_do_crypt(req);
		crypto_request_complete(areq, err);
	}
}

/*
 * Driver-owned unbound queue: queue_work_on still targets an
 * explicit CPU (cross-CPU proof), and the consumer can flush it so
 * no callback outlives a cancelled wait.
 */
static struct workqueue_struct *kxc_wq;

void kxc_flush_work(void)
{
	flush_workqueue(kxc_wq);
}

static void kxc_queue_drain(void)
{
	int cpu, ncpu;

	/* Cross-CPU completion: never the queueing CPU when one exists. */
	ncpu = num_online_cpus();
	cpu = ncpu > 1 ? (int)((smp_processor_id() + 1) % (unsigned int)ncpu) : 0;
	queue_work_on(cpu, kxc_wq, &kxc_drain_work);
}

void kxc_drain_kick(void)
{
	kxc_queue_drain();
}

void kxc_set_submit_hold(bool hold)
{
	atomic_set(&kxc_submit_hold, hold ? 1 : 0);
}

void kxc_set_delay_ms(int ms)
{
	atomic_set(&kxc_delay_ms, ms);
}

void kxc_set_inline_once(bool once)
{
	atomic_set(&kxc_inline_once, once ? 1 : 0);
}

static int kxc_async_crypt(struct skcipher_request *req)
{
	int err;

	/*
	 * P4r2 forced early completion: consume the one-shot and
	 * complete inline (no queue, no worker, no lock held across
	 * the completion — the nested resubmit path re-enters here
	 * with the shot already spent, so it queues normally).
	 * The -EINPROGRESS return still promises queued semantics:
	 * the terminal callback simply fired first.
	 */
	if (atomic_cmpxchg(&kxc_inline_once, 1, 0) == 1) {
		err = kxc_do_crypt(req);
		crypto_request_complete(&req->base, err);
		return -EINPROGRESS;
	}
	spin_lock_bh(&kxc_bq_lock);
	err = crypto_enqueue_request(&kxc_bq, &req->base);
	spin_unlock_bh(&kxc_bq_lock);
	if (err != -EINPROGRESS && err != -EBUSY)
		return err;
	if (!atomic_read(&kxc_submit_hold))
		kxc_queue_drain();
	return err;
}

static struct skcipher_alg kxc_sync_alg = {
	.base = {
		.cra_name = KXC_GENERIC_NAME,
		.cra_priority = 100,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct kxc_ctx),
		.cra_module = THIS_MODULE,
		.cra_init = kxc_cra_init,
		.cra_exit = kxc_cra_exit,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.setkey = kxc_setkey,
	.encrypt = kxc_sync_crypt,
	.decrypt = kxc_sync_crypt,
};

static struct skcipher_alg kxc_async_alg = {
	.base = {
		.cra_name = KXC_GENERIC_NAME,
		.cra_priority = 300,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct kxc_ctx),
		.cra_module = THIS_MODULE,
		.cra_init = kxc_cra_init,
		.cra_exit = kxc_cra_exit,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.setkey = kxc_setkey,
	.encrypt = kxc_async_crypt,
	.decrypt = kxc_async_crypt,
};

/*
 * Failing-init driver (T07 F03): registration succeeds, but every
 * allocation fails in cra_init with -EINVAL — the allocation
 * attempt/error truth without a fabricated transform. The
 * encrypt/decrypt/setkey callbacks are wired only because the
 * registration requires them; init fails first, so they are
 * unreachable (any call would be a loud logic error, but there
 * is no probe to trip — init gates everything).
 */
static int kxc_fail_cra_init(struct crypto_tfm *tfm)
{
	return -EINVAL;
}

static struct skcipher_alg kxc_fail_alg = {
	.base = {
		.cra_name = "kxcipher-broken",
		.cra_priority = 100,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct kxc_ctx),
		.cra_module = THIS_MODULE,
		.cra_init = kxc_fail_cra_init,
		.cra_exit = kxc_cra_exit,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.setkey = kxc_setkey,
	.encrypt = kxc_sync_crypt,
	.decrypt = kxc_sync_crypt,
};

/* ------------------------------------------------------------------ */
/* minimal AEAD driver (T07 F07 config shape; NOT T10 AEAD lifecycle)   */
/* ------------------------------------------------------------------ */

#define KXC_AEAD_GENERIC_NAME "kxaead"
#define KXC_AEAD_MAXAUTHSIZE 16

struct kxc_aead_ctx {
	u8 key[32];
	unsigned int keylen;
	unsigned int authsize;
};

static int kxc_aead_cra_init(struct crypto_tfm *tfm)
{
	struct kxc_aead_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

static void kxc_aead_cra_exit(struct crypto_tfm *tfm)
{
	struct kxc_aead_ctx *ctx = crypto_tfm_ctx(tfm);

	memzero_explicit(ctx, sizeof(*ctx));
}

static int kxc_aead_setkey(struct crypto_aead *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct kxc_aead_ctx *ctx = crypto_aead_ctx(tfm);

	if (keylen < 16 || keylen > sizeof(ctx->key))
		return -EINVAL;
	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;
	return 0;
}

static int kxc_aead_setauthsize(struct crypto_aead *tfm,
				unsigned int authsize)
{
	struct kxc_aead_ctx *ctx = crypto_aead_ctx(tfm);

	if (authsize == 0 || authsize > KXC_AEAD_MAXAUTHSIZE)
		return -EINVAL;
	ctx->authsize = authsize;
	return 0;
}

/*
 * XOR "AEAD": encrypt/decrypt mirror the skcipher walk over
 * cryptlen bytes. There are deliberately NO tag semantics here
 * (no authentication, assoc ignored): T07 exercises the
 * setauthsize CONFIGURATION shape only; T10 owns AEAD request
 * lifecycle, tag checks and failure legs. Single-sg test
 * buffers only (the scenario pins one page).
 */
static int kxc_aead_do_crypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct kxc_aead_ctx *ctx = crypto_aead_ctx(tfm);
	u8 *dst;
	const u8 *src;
	unsigned int i;

	if (!ctx->keylen)
		return -ENOKEY;
	if (!ctx->authsize)
		return -EINVAL;
	src = sg_virt(req->src);
	dst = sg_virt(req->dst);
	for (i = 0; i < req->cryptlen; i++)
		dst[i] = src[i] ^ ctx->key[i % ctx->keylen];
	return 0;
}

static int kxc_aead_encrypt(struct aead_request *req)
{
	return kxc_aead_do_crypt(req);
}

static int kxc_aead_decrypt(struct aead_request *req)
{
	return kxc_aead_do_crypt(req);
}

static struct aead_alg kxc_aead_alg = {
	.base = {
		.cra_name = KXC_AEAD_GENERIC_NAME,
		.cra_priority = 100,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct kxc_aead_ctx),
		.cra_module = THIS_MODULE,
		.cra_init = kxc_aead_cra_init,
		.cra_exit = kxc_aead_cra_exit,
	},
	.ivsize = 16,
	.maxauthsize = KXC_AEAD_MAXAUTHSIZE,
	.setkey = kxc_aead_setkey,
	.setauthsize = kxc_aead_setauthsize,
	.encrypt = kxc_aead_encrypt,
	.decrypt = kxc_aead_decrypt,
};

/* ------------------------------------------------------------------ */
/* debugfs control + ledger                                            */
/* ------------------------------------------------------------------ */

static struct dentry *kxc_debugfs_dir;

static ssize_t kxc_control_write(struct file *file, const char __user *buf,
				 size_t len, loff_t *ppos)
{
	char cmd[KXC_CMD_MAX + 1];
	char id[KXC_RUN_ID_MAX + 1];
	char scenario[KXC_SCENARIO_MAX + 1];
	unsigned long long seed;
	int nchars = 0;
	int ret;

	if (len == 0 || len > KXC_CMD_MAX)
		return -EINVAL;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';

	/*
	 * STOP takes only the stop lock (never the run lock): GO
	 * holds kxc_run_lock for the whole scenario, so a run-locking
	 * STOP could never interrupt it. Against a concurrently
	 * finishing GO the idle check is best-effort, but a stale
	 * flag is always cleared by the next PREPARE.
	 */
	if (!strcmp(cmd, "STOP\n") || !strcmp(cmd, "STOP")) {
		mutex_lock(&kxc_stop_lock);
		if (!READ_ONCE(kxc_run.prepared) || READ_ONCE(kxc_run.done))
			ret = -EALREADY;
		else {
			kxc_run_request_stop(&kxc_run);
			ret = (int)len;
		}
		mutex_unlock(&kxc_stop_lock);
		return ret;
	}

	mutex_lock(&kxc_run_lock);
	if (!strcmp(cmd, "GO\n") || !strcmp(cmd, "GO")) {
		if (!kxc_run.prepared) {
			ret = -EINVAL;
		} else if (kxc_run.done) {
			ret = -EALREADY;
		} else {
			ret = kxc_scenario_run(&kxc_run, kxc_run.scenario);
			kxc_ledger_emit(
				"{\"v\":1,\"run\":\"%s\",\"phase\":\"done\","
				"\"fixture_result\":%d,\"overflow\":%llu,\"ts\":%llu,"
				"\"entries\":%llu}",
				kxc_run.id, ret < 0 ? ret : 0,
				kxc_ledger_dropped(), ktime_get_ns(),
				(u64)atomic64_read(&kxc_crypt_entries));
			kxc_run_finish(&kxc_run, ret < 0 ? ret : 0);
			ret = ret < 0 ? ret : (int)len;
		}
	} else if (sscanf(cmd, "PREPARE %64s %32s %llu %n", id, scenario,
			   &seed, &nchars) == 3 &&
		   (cmd[nchars] == '\0' || cmd[nchars] == '\n')) {
		/* run_lock -> stop_lock order; STOP takes only stop_lock. */
		mutex_lock(&kxc_stop_lock);
		ret = kxc_run_begin(&kxc_run, id, scenario, (u64)seed);
		mutex_unlock(&kxc_stop_lock);
		ret = ret < 0 ? ret : (int)len;
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&kxc_run_lock);
	return ret;
}

static ssize_t kxc_control_read(struct file *file, char __user *buf,
				size_t len, loff_t *ppos)
{
	char status[256];
	int n;

	mutex_lock(&kxc_run_lock);
	n = scnprintf(status, sizeof(status),
		      "run=%s scenario=%s prepared=%d done=%d "
		      "fixture_result=%d rows=%d overflow=%llu entries=%llu\n",
		      kxc_run.prepared ? kxc_run.id : "-",
		      kxc_run.prepared ? kxc_run.scenario : "-",
		      kxc_run.prepared ? 1 : 0, kxc_run.done ? 1 : 0,
		      kxc_run.fixture_result, atomic_read(&kxc_log.count),
		      kxc_ledger_dropped(),
		      (u64)atomic64_read(&kxc_crypt_entries));
	mutex_unlock(&kxc_run_lock);
	return simple_read_from_buffer(buf, len, ppos, status, n);
}

static ssize_t kxc_ledger_read(struct file *file, char __user *buf,
			       size_t len, loff_t *ppos)
{
	loff_t pos = *ppos;
	size_t copied = 0;
	int i, count;

	if (pos < 0)
		return -EINVAL;
	spin_lock_bh(&kxc_log.lock);
	count = atomic_read(&kxc_log.count);
	for (i = 0; i < count && copied < len; i++) {
		size_t rowlen = (size_t)kxc_log.lens[i] + 1; /* + newline */
		char *row = kxc_log.rows[i];

		if (pos >= (loff_t)rowlen) {
			pos -= (loff_t)rowlen;
			continue;
		}
		while (pos < (loff_t)rowlen && copied < len) {
			char c = pos < (loff_t)kxc_log.lens[i] ? row[pos] : '\n';

			spin_unlock_bh(&kxc_log.lock);
			if (copy_to_user(buf + copied, &c, 1))
				return -EFAULT;
			spin_lock_bh(&kxc_log.lock);
			/*
			 * Re-validate: a concurrent PREPARE resets the
			 * ring. Count is re-read; rows/lens are stable
			 * while count covers them (reset only zeroes the
			 * count, never frees).
			 */
			count = atomic_read(&kxc_log.count);
			if (i >= count)
				break;
			pos++;
			copied++;
		}
		/* ppos advance per row is handled by the caller update. */
		pos = 0;
	}
	spin_unlock_bh(&kxc_log.lock);
	*ppos += (loff_t)copied;
	return (ssize_t)copied;
}

static const struct file_operations kxc_control_fops = {
	.owner = THIS_MODULE,
	.read = kxc_control_read,
	.write = kxc_control_write,
};

static const struct file_operations kxc_ledger_fops = {
	.owner = THIS_MODULE,
	.read = kxc_ledger_read,
};

/* ------------------------------------------------------------------ */
/* module                                                              */
/* ------------------------------------------------------------------ */

static int __init kxc_init(void)
{
	int ret;

	if (!kxc_token_ok(run_suffix, KXC_SUFFIX_MAX))
		return -EINVAL;
	scnprintf(kxc_sync_name, sizeof(kxc_sync_name), "kxcipher-sync-%s",
		  run_suffix);
	scnprintf(kxc_async_name, sizeof(kxc_async_name), "kxcipher-async-%s",
		  run_suffix);
	scnprintf(kxc_fail_name, sizeof(kxc_fail_name), "kxcipher-broken-%s",
		  run_suffix);
	scnprintf(kxc_aead_name, sizeof(kxc_aead_name), "kxaead-sync-%s",
		  run_suffix);
	strscpy(kxc_sync_alg.base.cra_driver_name, kxc_sync_name,
		sizeof(kxc_sync_alg.base.cra_driver_name));
	strscpy(kxc_async_alg.base.cra_driver_name, kxc_async_name,
		sizeof(kxc_async_alg.base.cra_driver_name));
	strscpy(kxc_fail_alg.base.cra_driver_name, kxc_fail_name,
		sizeof(kxc_fail_alg.base.cra_driver_name));
	strscpy(kxc_aead_alg.base.cra_driver_name, kxc_aead_name,
		sizeof(kxc_aead_alg.base.cra_driver_name));

	kxc_log.rows = vmalloc(array_size(sizeof(*kxc_log.rows), KXC_ROWS_MAX));
	if (!kxc_log.rows)
		return -ENOMEM;
	spin_lock_init(&kxc_log.lock);

	kxc_wq = alloc_workqueue("kxc_fix", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!kxc_wq) {
		vfree(kxc_log.rows);
		return -ENOMEM;
	}
	crypto_init_queue(&kxc_bq, KXC_BQ_MAX_QLEN);
	INIT_WORK(&kxc_drain_work, kxc_async_fn);
	atomic_set(&kxc_submit_hold, 0);
	atomic_set(&kxc_delay_ms, 0);

	kxc_debugfs_dir = debugfs_create_dir("kcrypto_fixture", NULL);
	debugfs_create_file("control", 0600, kxc_debugfs_dir, NULL,
			    &kxc_control_fops);
	debugfs_create_file("ledger", 0400, kxc_debugfs_dir, NULL,
			    &kxc_ledger_fops);

	ret = crypto_register_skcipher(&kxc_sync_alg);
	if (ret)
		goto err_alg;
	ret = crypto_register_skcipher(&kxc_async_alg);
	if (ret)
		goto err_async;
	ret = crypto_register_skcipher(&kxc_fail_alg);
	if (ret)
		goto err_fail;
	ret = crypto_register_aead(&kxc_aead_alg);
	if (ret)
		goto err_aead;

	pr_info("kcrypto_fixture: loaded (suffix %s, TEST ONLY)\n", run_suffix);
	return 0;

err_aead:
	crypto_unregister_skcipher(&kxc_fail_alg);
err_fail:
	crypto_unregister_skcipher(&kxc_async_alg);
err_async:
	crypto_unregister_skcipher(&kxc_sync_alg);
err_alg:
	debugfs_remove_recursive(kxc_debugfs_dir);
	destroy_workqueue(kxc_wq);
	vfree(kxc_log.rows);
	return ret;
}

static void __exit kxc_exit(void)
{
	crypto_unregister_aead(&kxc_aead_alg);
	crypto_unregister_skcipher(&kxc_fail_alg);
	crypto_unregister_skcipher(&kxc_async_alg);
	crypto_unregister_skcipher(&kxc_sync_alg);
	debugfs_remove_recursive(kxc_debugfs_dir);
	/*
	 * Queued completions are flushed here (and on every cancelled
	 * wait): async requests complete before GO returns, and rmmod
	 * during GO is excluded by the run mutex held across the
	 * scenario, but the destroy is the backstop either way.
	 * A nonempty backlog queue at unload is a fixture leak: loud.
	 */
	destroy_workqueue(kxc_wq);
	WARN_ON(crypto_queue_len(&kxc_bq) != 0);
	vfree(kxc_log.rows);
	pr_info("kcrypto_fixture: unloaded\n");
}

module_init(kxc_init);
module_exit(kxc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KryProbe");
MODULE_DESCRIPTION("kernel crypto truth fixture (TEST ONLY, no real crypto)");
