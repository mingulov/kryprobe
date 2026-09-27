// SPDX-License-Identifier: GPL-2.0-only
/*
 * kcrypto_fixture consumer: PREPARE/GO/STOP scenarios driving the
 * fixture drivers and emitting ledger truth rows (see fixture.h).
 *
 * TEST ONLY. Test bytes are copied only inside this fixture's own
 * operations; the observer captures metadata only.
 */
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/ktime.h>
#include <linux/refcount.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>

#include "fixture.h"

#define KXC_BLOCK 16
#define KXC_KEYLEN 16
#define KXC_IVLEN 16
/* Async wait sliced so STOP can abort the run. */
#define KXC_WAIT_SLICE_MS 100
#define KXC_WAIT_SLICES 100
/* Backlog burst width (concurrent MAY_BACKLOG requests, one tfm). */
#define KXC_BURST_NREQS 4
/* Delayed-completion provider delay per async completion (ms). */
#define KXC_DELAY_MS 200

static const u8 kxc_key[KXC_KEYLEN] = "0123456789abcdef";
static const u8 kxc_pt[KXC_BLOCK] = "fedcba9876543210";
static const u8 kxc_iv[KXC_IVLEN] = "iviviviviviviviv";

struct kxc_op {
	struct kxc_run *run;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	struct page *page;
	u8 iv[KXC_IVLEN];
	struct completion done;
	/*
	 * Serializes the waiter's progress marker against the
	 * callback's terminal row: whichever runs first observes
	 * true state, so a progress row can never claim in-flight
	 * after the terminal landed (or vice versa). Lock order:
	 * mark_lock -> ledger lock, never the reverse. The callback
	 * never touches op after complete(): it sets completed and
	 * unlocks first, so the waiter cannot release stack op
	 * while the callback still uses it.
	 */
	spinlock_t mark_lock;
	bool completed;
	int err;
	u64 seq;
};

/* ------------------------------------------------------------------ */
/* row emission                                                        */
/* ------------------------------------------------------------------ */

static void kxc_emit_alloc(struct kxc_run *run, u64 seq, const char *req_name,
			   const char *drv, u32 type, u32 mask)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"alloc\","
		"\"req\":\"%s\",\"drv\":\"%s\",\"type\":%u,\"mask\":%u,"
		"\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, req_name, drv, type, mask, ktime_get_ns(),
		smp_processor_id());
}

static void kxc_emit_config(struct kxc_run *run, u64 seq, const char *op,
			    int errno_, unsigned int len)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"config\","
		"\"op\":\"%s\",\"errno\":%d,\"len\":%u,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, op, errno_, len, ktime_get_ns(),
		smp_processor_id());
}

static void kxc_emit_free(struct kxc_run *run, u64 seq, bool final_free)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"free\","
		"\"final\":%s,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, final_free ? "true" : "false", ktime_get_ns(),
		smp_processor_id());
}

static void kxc_emit_submit(struct kxc_run *run, u64 seq, const char *op,
			    unsigned int len, u32 flags)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"submit\","
		"\"op\":\"%s\",\"len\":%u,\"flags\":%u,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, op, len, flags, ktime_get_ns(),
		smp_processor_id());
}

static void kxc_emit_return(struct kxc_run *run, u64 seq, int errno_)
{
	/*
	 * P3r provider-entry marker: the body-entry count at emit time
	 * (after the call returned, so it includes this op's entry if
	 * the provider ran). Extra field, ignored by older oracles.
	 */
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"return\","
		"\"errno\":%d,\"ts\":%llu,\"cpu\":%u,\"entries\":%llu}",
		run->id, seq, errno_, ktime_get_ns(),
		smp_processor_id(), kxc_crypt_entries_count());
}

static void kxc_emit_progress(struct kxc_run *run, u64 seq, int errno_)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"progress\","
		"\"errno\":%d,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, errno_, ktime_get_ns(), smp_processor_id());
}

static void kxc_emit_terminal(struct kxc_run *run, u64 seq, int errno_)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"terminal\","
		"\"errno\":%d,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, errno_, ktime_get_ns(), smp_processor_id());
}

/* ------------------------------------------------------------------ */
/* operation setup/teardown                                            */
/* ------------------------------------------------------------------ */

static void kxc_complete(void *data, int err)
{
	struct kxc_op *op = data;

	op->err = err;
	/*
	 * Terminal truth is recorded HERE (completion context), never
	 * inferred by the observer: CPU proves cross-CPU delivery.
	 * Under the mark lock, so a concurrent progress sample
	 * observes true state. completed is set and the lock
	 * released BEFORE complete(): op lives on the waiter's
	 * stack, and touching it after the wake would race the
	 * waiter's teardown.
	 */
	spin_lock_bh(&op->mark_lock);
	kxc_emit_terminal(op->run, op->seq, err);
	op->completed = true;
	spin_unlock_bh(&op->mark_lock);
	complete(&op->done);
}

/*
 * Truthful progress marker: sample completed under the mark lock
 * so the sample and the marker are atomic against the callback's
 * terminal row (0 iff the terminal landed, in either order).
 */
static void kxc_mark_progress(struct kxc_run *run, struct kxc_op *op,
			      u64 seq)
{
	int marker;

	spin_lock_bh(&op->mark_lock);
	marker = op->completed ? 0 : -EINPROGRESS;
	kxc_emit_progress(run, seq, marker);
	spin_unlock_bh(&op->mark_lock);
}

static void kxc_tfm_release(struct kxc_run *run, struct crypto_skcipher *tfm,
			    u64 aseq);

static int kxc_tfm_acquire_typed(struct kxc_run *run, const char *req_name,
				       u32 type, u32 mask,
				       struct crypto_skcipher **tfm, u64 *aseq)
{
	struct crypto_skcipher *t;
	int err;

	t = crypto_alloc_skcipher(req_name, type, mask);
	if (IS_ERR(t))
		return PTR_ERR(t);
	*aseq = kxc_next_seq(run);
	kxc_emit_alloc(run, *aseq, req_name,
		       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(t)),
		       type, mask);
	/* T07-R2-04: the setup setkey is hooked sensor traffic — it
	 * rides the transcript as its own config row (success or
	 * failure), so the transform oracle compares complete
	 * fixture truth, never a silent setup step. */
	err = crypto_skcipher_setkey(t, kxc_key, KXC_KEYLEN);
	kxc_emit_config(run, *aseq, "setkey", err, KXC_KEYLEN);
	if (err) {
		kxc_tfm_release(run, t, *aseq);
		return -EKEYREJECTED;
	}
	*tfm = t;
	return 0;
}

static int kxc_tfm_acquire(struct kxc_run *run, const char *req_name,
			   struct crypto_skcipher **tfm, u64 *aseq)
{
	return kxc_tfm_acquire_typed(run, req_name, 0, 0, tfm, aseq);
}

/*
 * Raw skcipher acquisition: alloc + alloc row, NO setkey. For
 * scenarios that drive configurations explicitly (every setkey
 * they run is emitted as its own config row — including the
 * setup setkey, which kxc_tfm_acquire_typed records as well).
 */
static int kxc_tfm_acquire_raw(struct kxc_run *run, const char *req_name,
			       struct crypto_skcipher **tfm, u64 *aseq)
{
	struct crypto_skcipher *t;

	t = crypto_alloc_skcipher(req_name, 0, 0);
	if (IS_ERR(t))
		return PTR_ERR(t);
	*aseq = kxc_next_seq(run);
	kxc_emit_alloc(run, *aseq, req_name,
		       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(t)),
		       0, 0);
	*tfm = t;
	return 0;
}

/* Raw AEAD acquisition: alloc + alloc row, no setkey/setauthsize. */
static int kxc_aead_acquire(struct kxc_run *run, const char *req_name,
			    struct crypto_aead **tfm, u64 *aseq)
{
	struct crypto_aead *t;

	t = crypto_alloc_aead(req_name, 0, 0);
	if (IS_ERR(t))
		return PTR_ERR(t);
	*aseq = kxc_next_seq(run);
	kxc_emit_alloc(run, *aseq, req_name,
		       crypto_tfm_alg_driver_name(crypto_aead_tfm(t)),
		       0, 0);
	*tfm = t;
	return 0;
}

static void kxc_aead_release(struct kxc_run *run, struct crypto_aead *tfm,
			     u64 aseq)
{
	crypto_free_aead(tfm);
	/* Fixture AEAD transforms are never shared: every free is final. */
	kxc_emit_free(run, aseq, true);
}

static void kxc_tfm_release(struct kxc_run *run, struct crypto_skcipher *tfm,
			    u64 aseq)
{
	crypto_free_skcipher(tfm);
	/* Fixture transforms are never shared: every free is final. */
	kxc_emit_free(run, aseq, true);
}

static int kxc_req_setup(struct kxc_run *run, struct crypto_skcipher *tfm,
			 struct kxc_op *op, u32 cb_flags, unsigned int buflen)
{
	u8 *buf;

	memset(op, 0, sizeof(*op));
	op->run = run;
	op->tfm = tfm;
	op->req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!op->req)
		return -ENOMEM;
	op->page = alloc_page(GFP_KERNEL);
	if (!op->page) {
		skcipher_request_free(op->req);
		op->req = NULL;
		return -ENOMEM;
	}
	buf = page_address(op->page);
	memcpy(buf, kxc_pt, min_t(unsigned int, buflen, KXC_BLOCK));
	sg_init_one(&op->sg, buf, buflen);
	skcipher_request_set_callback(op->req, cb_flags, kxc_complete, op);
	memcpy(op->iv, kxc_iv, KXC_IVLEN);
	skcipher_request_set_crypt(op->req, &op->sg, &op->sg, buflen,
				   op->iv);
	init_completion(&op->done);
	spin_lock_init(&op->mark_lock);
	op->completed = false;
	op->err = -EINPROGRESS;
	return 0;
}

static void kxc_req_teardown(struct kxc_op *op)
{
	skcipher_request_free(op->req);
	op->req = NULL;
	__free_page(op->page);
	op->page = NULL;
}

static int kxc_op_prepare(struct kxc_run *run, struct kxc_op *op,
			  const char *drv_name, u64 *aseq)
{
	struct crypto_skcipher *tfm;
	int err;

	err = kxc_tfm_acquire(run, drv_name, &tfm, aseq);
	if (err)
		return err;
	err = kxc_req_setup(run, tfm, op, 0, KXC_BLOCK);
	if (err) {
		kxc_tfm_release(run, tfm, *aseq);
		return err;
	}
	return 0;
}

static void kxc_op_release(struct kxc_run *run, struct kxc_op *op, u64 aseq)
{
	struct crypto_skcipher *tfm = op->tfm;

	kxc_req_teardown(op);
	kxc_tfm_release(run, tfm, aseq);
}

static int kxc_wait_done(struct kxc_run *run, struct kxc_op *op)
{
	int i;

	for (i = 0; i < KXC_WAIT_SLICES; i++) {
		if (kxc_run_stop_requested(run)) {
			/*
			 * No callback may touch op/ledger after we
			 * return: flush the driver queue first. The
			 * flush normally delivers the callback's own
			 * terminal row; the waiter records one only
			 * when completion is genuinely missing (no
			 * duplicate possible: nothing is in flight
			 * after the flush). Either way the nonzero
			 * result rejects the run honestly.
			 */
			kxc_flush_work();
			if (!completion_done(&op->done))
				kxc_emit_terminal(run, op->seq, -ECANCELED);
			return -ECANCELED;
		}
		if (wait_for_completion_timeout(&op->done,
						msecs_to_jiffies(KXC_WAIT_SLICE_MS)))
			return op->err;
	}
	kxc_flush_work();
	if (!completion_done(&op->done))
		kxc_emit_terminal(run, op->seq, -ETIMEDOUT);
	return -ETIMEDOUT;
}

/* ------------------------------------------------------------------ */
/* scenarios                                                           */
/* ------------------------------------------------------------------ */

static int kxc_scenario_sync_once(struct kxc_run *run)
{
	struct kxc_op op;
	u64 aseq, seq;
	int err;

	err = kxc_op_prepare(run, &op, kxc_sync_driver_name(), &aseq);
	if (err)
		return err;
	/* Encrypt, then decrypt back, verifying the roundtrip. */
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK, 0);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	/* A synchronous return IS the terminal result: record both rows. */
	kxc_emit_terminal(run, seq, err);
	if (err)
		goto out;
	memcpy(op.iv, kxc_iv, KXC_IVLEN);
	skcipher_request_set_crypt(op.req, &op.sg, &op.sg, KXC_BLOCK, op.iv);
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "decrypt", KXC_BLOCK, 0);
	err = crypto_skcipher_decrypt(op.req);
	kxc_emit_return(run, seq, err);
	kxc_emit_terminal(run, seq, err);
	if (err)
		goto out;
	if (memcmp(page_address(op.page), kxc_pt, KXC_BLOCK))
		err = -EBADMSG;
out:
	kxc_op_release(run, &op, aseq);
	return err;
}

static int kxc_scenario_async_once(struct kxc_run *run)
{
	struct kxc_op op;
	u64 aseq, seq;
	int err;

	err = kxc_op_prepare(run, &op, kxc_async_driver_name(), &aseq);
	if (err)
		return err;
	seq = kxc_next_seq(run);
	op.seq = seq;
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK, 0);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	if (err != -EINPROGRESS) {
		/* Async driver returned synchronously: terminal is here. */
		kxc_emit_terminal(run, seq, err);
		kxc_op_release(run, &op, aseq);
		return err;
	}
	/*
	 * Terminal row arrives via kxc_complete (completion context).
	 * The wait existing at all proves the callback ran: a missing
	 * terminal is -ETIMEDOUT, never an assumed success.
	 */
	err = kxc_wait_done(run, &op);
	kxc_op_release(run, &op, aseq);
	return err;
}

static int kxc_scenario_delayed_completion(struct kxc_run *run)
{
	struct kxc_op op;
	u64 aseq, seq, t0, elapsed_ms;
	int err;

	err = kxc_op_prepare(run, &op, kxc_async_driver_name(), &aseq);
	if (err)
		return err;
	/*
	 * Genuine slow completion: the provider delays every async
	 * completion by KXC_DELAY_MS. The progress row below is a
	 * true in-flight marker (completion still pending), and the
	 * elapsed check verifies the delay was honored. Delay is
	 * cleared on every exit so no later scenario inherits it.
	 */
	kxc_set_delay_ms(KXC_DELAY_MS);
	seq = kxc_next_seq(run);
	op.seq = seq;
	kxc_emit_submit(run, seq, "encrypt-delayed", KXC_BLOCK, 0);
	t0 = ktime_get_ns();
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	if (err != -EINPROGRESS) {
		kxc_emit_terminal(run, seq, err);
		kxc_set_delay_ms(0);
		kxc_op_release(run, &op, aseq);
		return err;
	}
	kxc_mark_progress(run, &op, seq);
	err = kxc_wait_done(run, &op);
	elapsed_ms = (ktime_get_ns() - t0) / 1000000;
	kxc_set_delay_ms(0);
	if (!err && elapsed_ms < KXC_DELAY_MS / 2)
		err = -EPROTO;
	kxc_op_release(run, &op, aseq);
	return err;
}

static int kxc_scenario_backlog_accepted(struct kxc_run *run)
{
	struct crypto_skcipher *tfm;
	struct kxc_op ops[KXC_BURST_NREQS];
	u64 aseq, seqs[KXC_BURST_NREQS];
	bool pending[KXC_BURST_NREQS] = { false };
	int err, first_err = 0;
	int i, nsetup = 0;

	err = kxc_tfm_acquire(run, kxc_async_driver_name(), &tfm, &aseq);
	if (err)
		return err;
	/*
	 * Hold the drain while submitting: with the depth-1 driver
	 * queue, submit 0 deterministically returns -EINPROGRESS
	 * and submits 1..3 deterministically return -EBUSY (genuine
	 * backlog, not timing). Any deviation fails the run loudly.
	 */
	kxc_set_submit_hold(true);
	for (i = 0; i < KXC_BURST_NREQS; i++) {
		err = kxc_req_setup(run, tfm, &ops[i],
				    CRYPTO_TFM_REQ_MAY_BACKLOG, KXC_BLOCK);
		if (err) {
			if (!first_err)
				first_err = err;
			goto teardown;
		}
		nsetup++;
		seqs[i] = kxc_next_seq(run);
		ops[i].seq = seqs[i];
		pending[i] = false;
	}
	for (i = 0; i < KXC_BURST_NREQS; i++) {
		int expected = i == 0 ? -EINPROGRESS : -EBUSY;

		kxc_emit_submit(run, seqs[i], "encrypt-burst", KXC_BLOCK,
				    CRYPTO_TFM_REQ_MAY_BACKLOG);
		err = crypto_skcipher_encrypt(ops[i].req);
		kxc_emit_return(run, seqs[i], err);
		if (err == -EINPROGRESS || err == -EBUSY) {
			/*
			 * Queued (normally or as backlog): the
			 * terminal row still arrives via callback,
			 * so this op MUST be waited even when the
			 * return deviates from the script.
			 */
			pending[i] = true;
			if (err != expected && !first_err)
				first_err = -EPROTO;
		} else {
			/* Synchronous return is always a deviation. */
			kxc_emit_terminal(run, seqs[i], err);
			if (!first_err)
				first_err = -EPROTO;
		}
	}
teardown:
	/* Always release the hold and kick the drain: no stuck queue. */
	kxc_set_submit_hold(false);
	kxc_drain_kick();
	for (i = 0; i < KXC_BURST_NREQS; i++) {
		if (!pending[i])
			continue;
		err = kxc_wait_done(run, &ops[i]);
		if (err && !first_err)
			first_err = err;
	}
	for (i = 0; i < nsetup; i++)
		kxc_req_teardown(&ops[i]);
	kxc_tfm_release(run, tfm, aseq);
	return first_err;
}

static int kxc_scenario_early_callback(struct kxc_run *run)
{
	struct kxc_op op;
	u64 aseq, seq;
	int err;

	err = kxc_op_prepare(run, &op, kxc_async_driver_name(), &aseq);
	if (err)
		return err;
	seq = kxc_next_seq(run);
	op.seq = seq;
	kxc_emit_submit(run, seq, "encrypt-early", KXC_BLOCK, 0);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	if (err != -EINPROGRESS) {
		kxc_emit_terminal(run, seq, err);
		kxc_op_release(run, &op, aseq);
		return err;
	}
	/*
	 * Poll before waiting: exactly one progress row lands (two
	 * notifications total), truthful in either order via the
	 * mark helper (0 iff the terminal already landed).
	 */
	kxc_mark_progress(run, &op, seq);
	err = kxc_wait_done(run, &op);
	kxc_op_release(run, &op, aseq);
	return err;
}

static int kxc_scenario_exact_driver(struct kxc_run *run)
{
	struct kxc_op op;
	const char *resolved;
	u64 aseq, seq;
	int err;

	/*
	 * Request the GENERIC name: the crypto API must resolve it
	 * to exactly the async fixture driver (highest priority).
	 * Anything else rejects the run honestly.
	 */
	err = kxc_op_prepare(run, &op, KXC_GENERIC_NAME, &aseq);
	if (err)
		return err;
	resolved = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(op.tfm));
	if (strcmp(resolved, kxc_async_driver_name())) {
		kxc_op_release(run, &op, aseq);
		return -ENODEV;
	}
	seq = kxc_next_seq(run);
	op.seq = seq;
	kxc_emit_submit(run, seq, "encrypt-exact", KXC_BLOCK, 0);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	if (err != -EINPROGRESS) {
		kxc_emit_terminal(run, seq, err);
		kxc_op_release(run, &op, aseq);
		return err;
	}
	err = kxc_wait_done(run, &op);
	kxc_op_release(run, &op, aseq);
	return err;
}

static int kxc_scenario_failed_alloc(struct kxc_run *run)
{
	struct crypto_skcipher *tfm;
	u64 seq;
	int err;

	tfm = crypto_alloc_skcipher("kxcipher-no-such", 0, 0);
	if (!IS_ERR(tfm)) {
		/* Impossible: no such driver exists. Fail loudly. */
		crypto_free_skcipher(tfm);
		return -EEXIST;
	}
	err = PTR_ERR(tfm);
	/*
	 * Only the expected ENOENT completes the scenario: any
	 * other allocation error is unexpected behavior and fails
	 * the run honestly (nonzero DONE rejects the truth).
	 */
	if (err != -ENOENT)
		return err;
	/*
	 * The failed allocation IS the recorded invocation: a
	 * submit/return/terminal triple carrying the native errno,
	 * and no alloc row (nothing was allocated). The "alloc-probe"
	 * op marks it as a probe, not a skcipher invocation. The
	 * scenario itself completed, so the run result is 0.
	 */
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "alloc-probe", 0, 0);
	kxc_emit_return(run, seq, err);
	kxc_emit_terminal(run, seq, err);
	return 0;
}

static int kxc_scenario_refheld_release(struct kxc_run *run)
{
	struct kxc_op op;
	u64 aseq;
	int err;

	/*
	 * Hold the transform reference across the run with zero
	 * invocations, then release it: alloc/free rows only.
	 */
	err = kxc_op_prepare(run, &op, kxc_sync_driver_name(), &aseq);
	if (err)
		return err;
	kxc_op_release(run, &op, aseq);
	return 0;
}

/* T07 F02: exact sync driver, untyped then restricted. */
static int kxc_scenario_typed_sync(struct kxc_run *run)
{
	struct crypto_skcipher *t1, *t2;
	u64 aseq1, aseq2;
	int err;

	err = kxc_tfm_acquire_typed(run, kxc_sync_driver_name(), 0, 0,
				    &t1, &aseq1);
	if (err)
		return err;
	err = kxc_tfm_acquire_typed(run, kxc_sync_driver_name(),
				    CRYPTO_ALG_TYPE_SKCIPHER,
				    CRYPTO_ALG_TYPE_MASK | CRYPTO_ALG_ASYNC,
				    &t2, &aseq2);
	if (err) {
		kxc_tfm_release(run, t1, aseq1);
		return err;
	}
	kxc_tfm_release(run, t2, aseq2);
	kxc_tfm_release(run, t1, aseq1);
	return 0;
}

/* T07 F03: the failing provider rejects allocation in cra_init. */
static int kxc_scenario_failed_init(struct kxc_run *run)
{
	struct crypto_skcipher *tfm;
	u64 seq;
	int err;

	tfm = crypto_alloc_skcipher(kxc_fail_driver_name(), 0, 0);
	if (!IS_ERR(tfm)) {
		/* Impossible: init always fails. Fail loudly. */
		crypto_free_skcipher(tfm);
		return -EEXIST;
	}
	err = PTR_ERR(tfm);
	/* Only the init errno completes the scenario: anything else
	 * is unexpected behavior and fails the run honestly. */
	if (err != -EINVAL)
		return err;
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "alloc-probe", 0, 0);
	kxc_emit_return(run, seq, err);
	kxc_emit_terminal(run, seq, err);
	return 0;
}

/*
 * T07 F04: release at refcount 2 (no free), then the proved final
 * free. 6.12/7.0 only: 7.2 removed the tfm refcount (destroy is
 * unconditional there), so the shared case cannot exist and the
 * scenario refuses with -EOPNOTSUPP. Soundness: the bump is
 * verified BEFORE any destroy (always safe); destroy#1's dec-test
 * hold is source-proven (see evidence/kcrypto-t07/
 * destroy-semantics.md) — a regression double-frees and oopses
 * LOUD, never a silent pass. No post-destroy reads.
 */
static int kxc_scenario_shared_release(struct kxc_run *run)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
	return -EOPNOTSUPP;
#else
	struct crypto_skcipher *t;
	struct crypto_tfm *base;
	u64 aseq;
	int err;

	/* Build-time proof the refcount field exists on this
	 * target: a missing field fails the build, never a
	 * silent fallback. */
	(void)sizeof(((struct crypto_tfm *)0)->refcnt);

	err = kxc_tfm_acquire(run, kxc_sync_driver_name(), &t, &aseq);
	if (err)
		return err;
	base = crypto_skcipher_tfm(t);
	/* Simulate the second holder: nothing in mainline takes one,
	 * so the fixture holds it directly. TEST ONLY. */
	refcount_inc(&base->refcnt);
	if (refcount_read(&base->refcnt) != 2) {
		crypto_free_skcipher(t);
		return -EPROTO;
	}
	crypto_free_skcipher(t);
	kxc_emit_free(run, aseq, false);
	crypto_free_skcipher(t);
	kxc_emit_free(run, aseq, true);
	return 0;
#endif
}

/* T07 F06: one thousand alloc/free lifetimes, back to back. */
#define KXC_REUSE_BURST 1000

static int kxc_scenario_reuse_burst(struct kxc_run *run)
{
	struct crypto_skcipher *t;
	u64 aseq;
	int i, err;

	for (i = 0; i < KXC_REUSE_BURST; i++) {
		err = kxc_tfm_acquire(run, kxc_sync_driver_name(), &t, &aseq);
		if (err)
			return err;
		kxc_tfm_release(run, t, aseq);
	}
	return 0;
}

/* T07 F07 skcipher leg: setkey ok, encrypt, rejected short key. */
#define KXC_SHORT_KEYLEN 7

static int kxc_scenario_rekey(struct kxc_run *run)
{
	struct crypto_skcipher *tfm;
	struct kxc_op op;
	u64 aseq, seq;
	int err;

	err = kxc_tfm_acquire_raw(run, kxc_sync_driver_name(), &tfm, &aseq);
	if (err)
		return err;
	err = crypto_skcipher_setkey(tfm, kxc_key, KXC_KEYLEN);
	kxc_emit_config(run, aseq, "setkey", err, KXC_KEYLEN);
	if (err)
		goto out_free;
	err = kxc_req_setup(run, tfm, &op, 0, KXC_BLOCK);
	if (err)
		goto out_free;
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK, 0);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	kxc_emit_terminal(run, seq, err);
	kxc_req_teardown(&op);
	if (err)
		goto out_free;
	err = crypto_skcipher_setkey(tfm, kxc_key, KXC_SHORT_KEYLEN);
	kxc_emit_config(run, aseq, "setkey", err, KXC_SHORT_KEYLEN);
	/* The short key MUST be rejected: anything else (including a
	 * silent accept) fails the run honestly. */
	if (err != -EINVAL) {
		err = err ? err : -EPROTO;
		goto out_free;
	}
	err = 0;
out_free:
	kxc_tfm_release(run, tfm, aseq);
	return err;
}

/* T07 F07 AEAD leg: valid authsize, encrypt, oversize authsize. */
#define KXC_AEAD_AUTHSIZE_OK 16
#define KXC_AEAD_AUTHSIZE_BIG 64

static int kxc_scenario_authsize(struct kxc_run *run)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg;
	struct page *page;
	u8 *buf;
	u8 iv[KXC_IVLEN];
	u64 aseq, seq;
	int err;

	err = kxc_aead_acquire(run, kxc_aead_driver_name(), &tfm, &aseq);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, kxc_key, KXC_KEYLEN);
	kxc_emit_config(run, aseq, "setkey", err, KXC_KEYLEN);
	if (err)
		goto out_free;
	err = crypto_aead_setauthsize(tfm, KXC_AEAD_AUTHSIZE_OK);
	kxc_emit_config(run, aseq, "setauthsize", err, KXC_AEAD_AUTHSIZE_OK);
	if (err)
		goto out_free;
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_free;
	}
	page = alloc_page(GFP_KERNEL);
	if (!page) {
		aead_request_free(req);
		err = -ENOMEM;
		goto out_free;
	}
	buf = page_address(page);
	memcpy(buf, kxc_pt, KXC_BLOCK);
	sg_init_one(&sg, buf, KXC_BLOCK);
	/* Sync-only: no completion callback; the driver returns directly. */
	aead_request_set_callback(req, 0, NULL, NULL);
	memcpy(iv, kxc_iv, KXC_IVLEN);
	aead_request_set_crypt(req, &sg, &sg, KXC_BLOCK, iv);
	aead_request_set_ad(req, 0);
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK, 0);
	err = crypto_aead_encrypt(req);
	kxc_emit_return(run, seq, err);
	kxc_emit_terminal(run, seq, err);
	aead_request_free(req);
	__free_page(page);
	if (err)
		goto out_free;
	err = crypto_aead_setauthsize(tfm, KXC_AEAD_AUTHSIZE_BIG);
	kxc_emit_config(run, aseq, "setauthsize", err, KXC_AEAD_AUTHSIZE_BIG);
	/* Oversize MUST be rejected: a silent accept fails honestly. */
	if (err != -EINVAL) {
		err = err ? err : -EPROTO;
		goto out_free;
	}
	err = 0;
out_free:
	kxc_aead_release(run, tfm, aseq);
	return err;
}

/* P3 sync request-metadata truth: exact-driver sync alloc + setkey
 * (epoch 1), a first op phase with varied cryptlen/flags, a second
 * setkey (epoch 2), then a second op phase. Every op records its
 * submit (op/len/flags), return (errno) and terminal (errno) rows —
 * the T08 oracle matches the observer's per-request metadata,
 * submit-pinned epochs, exact errnos and submit→return spans against
 * these rows in order. Flags are READ BACK from the request after
 * set_callback (self-verifying truth, not an echoed constant).
 */
#define KXC_META_BUFLEN 256
static int kxc_scenario_sync_meta(struct kxc_run *run)
{
	static const unsigned int lens[] = { 16, 64, 256 };
	static const u32 flagsets[] = { 0, CRYPTO_TFM_REQ_MAY_BACKLOG };
	struct crypto_skcipher *tfm;
	struct kxc_op op;
	u64 aseq, seq;
	u8 *buf;
	int i, err;

	err = kxc_tfm_acquire(run, kxc_sync_driver_name(), &tfm, &aseq);
	if (err)
		return err;
	err = kxc_req_setup(run, tfm, &op, 0, KXC_META_BUFLEN);
	if (err)
		goto out_free;
	/* Deterministic pattern over the whole buffer: every op length
	 * roundtrips verifiable bytes (alloc_page is NOT zeroed). */
	buf = page_address(op.page);
	memset(buf, 0xA5, KXC_META_BUFLEN);
	for (i = 0; i < 6; i++) {
		unsigned int len = lens[i % 3];
		u32 want = flagsets[i % 2];
		u32 got;

		/* Second keying era halfway through the ops. */
		if (i == 3) {
			err = crypto_skcipher_setkey(tfm, kxc_key,
						     KXC_KEYLEN);
			kxc_emit_config(run, aseq, "setkey", err,
					KXC_KEYLEN);
			if (err)
				goto out_teardown;
		}
		skcipher_request_set_callback(op.req, want, kxc_complete,
					      &op);
		got = op.req->base.flags;
		memcpy(op.iv, kxc_iv, KXC_IVLEN);
		skcipher_request_set_crypt(op.req, &op.sg, &op.sg, len,
					   op.iv);
		seq = kxc_next_seq(run);
		kxc_emit_submit(run, seq, "encrypt", len, got);
		err = crypto_skcipher_encrypt(op.req);
		kxc_emit_return(run, seq, err);
		kxc_emit_terminal(run, seq, err);
		if (err)
			goto out_teardown;
		memcpy(op.iv, kxc_iv, KXC_IVLEN);
		skcipher_request_set_crypt(op.req, &op.sg, &op.sg, len,
					   op.iv);
		seq = kxc_next_seq(run);
		kxc_emit_submit(run, seq, "decrypt", len, got);
		err = crypto_skcipher_decrypt(op.req);
		kxc_emit_return(run, seq, err);
		kxc_emit_terminal(run, seq, err);
		if (err)
			goto out_teardown;
		/* The decrypt must restore the pre-encrypt pattern:
		 * proves the op actually ran (not a skipped call). */
		if (memchr_inv(buf, 0xA5, len)) {
			err = -EBADMSG;
			goto out_teardown;
		}
	}
	err = 0;
out_teardown:
	kxc_req_teardown(&op);
out_free:
	kxc_tfm_release(run, tfm, aseq);
	return err;
}

/*
 * P3r sync ENOKEY truth: ops with no usable key must be refused early
 * by the crypto wrapper (-ENOKEY) WITHOUT entering the provider body.
 * Two ops run before any setkey; then a short (rejected) setkey lands
 * as its own failed config row; then two more ops. Every op records
 * submit/return/terminal rows; the return rows + done trailer carry
 * the provider-entry marker, which must read 0 throughout. The
 * scenario asserts only the errno behavior loudly; the entry marker
 * is the oracle's independent truth (errno alone is ambiguous: the
 * provider itself returns -ENOKEY after entry when keyless). Buffers
 * start patterned and must be untouched (no crypt work happened).
 */
static int kxc_scenario_sync_enokey(struct kxc_run *run)
{
	static const unsigned int lens[] = { 16, 64, 256, 16 };
	static const u32 flagsets[] = { 0, CRYPTO_TFM_REQ_MAY_BACKLOG };
	struct crypto_skcipher *tfm;
	struct kxc_op op;
	u64 aseq, seq;
	u8 *buf;
	int i, err;

	err = kxc_tfm_acquire_raw(run, kxc_sync_driver_name(), &tfm, &aseq);
	if (err)
		return err;
	err = kxc_req_setup(run, tfm, &op, 0, KXC_META_BUFLEN);
	if (err)
		goto out_free;
	buf = page_address(op.page);
	memset(buf, 0xA5, KXC_META_BUFLEN);
	for (i = 0; i < 4; i++) {
		unsigned int len = lens[i];
		u32 want = flagsets[i % 2];
		u32 got;

		/* Rejected key setup halfway through: the wrapper fails,
		 * the keying era must not move. */
		if (i == 2) {
			err = crypto_skcipher_setkey(tfm, kxc_key,
						     KXC_SHORT_KEYLEN);
			kxc_emit_config(run, aseq, "setkey", err,
					KXC_SHORT_KEYLEN);
			if (err != -EINVAL) {
				err = err ? err : -EPROTO;
				goto out_teardown;
			}
		}
		skcipher_request_set_callback(op.req, want, kxc_complete,
					      &op);
		got = op.req->base.flags;
		memcpy(op.iv, kxc_iv, KXC_IVLEN);
		skcipher_request_set_crypt(op.req, &op.sg, &op.sg, len,
					   op.iv);
		seq = kxc_next_seq(run);
		if ((i % 2) == 0) {
			kxc_emit_submit(run, seq, "encrypt", len, got);
			err = crypto_skcipher_encrypt(op.req);
		} else {
			kxc_emit_submit(run, seq, "decrypt", len, got);
			err = crypto_skcipher_decrypt(op.req);
		}
		kxc_emit_return(run, seq, err);
		kxc_emit_terminal(run, seq, err);
		/*
		 * Early wrapper refusal ONLY: any other result (success,
		 * a provider error, or a different errno) fails the run
		 * honestly.
		 */
		if (err != -ENOKEY) {
			err = err ? err : -EPROTO;
			goto out_teardown;
		}
		/* Refused ops perform no crypt work: the pattern is intact. */
		if (memchr_inv(buf, 0xA5, len)) {
			err = -EBADMSG;
			goto out_teardown;
		}
	}
	err = 0;
out_teardown:
	kxc_req_teardown(&op);
out_free:
	kxc_tfm_release(run, tfm, aseq);
	return err;
}

int kxc_scenario_run(struct kxc_run *run, const char *scenario)
{
	if (!strcmp(scenario, "sync-once"))
		return kxc_scenario_sync_once(run);
	if (!strcmp(scenario, "async-once"))
		return kxc_scenario_async_once(run);
	if (!strcmp(scenario, "delayed-completion"))
		return kxc_scenario_delayed_completion(run);
	if (!strcmp(scenario, "backlog-accepted"))
		return kxc_scenario_backlog_accepted(run);
	if (!strcmp(scenario, "early-callback"))
		return kxc_scenario_early_callback(run);
	if (!strcmp(scenario, "exact-driver"))
		return kxc_scenario_exact_driver(run);
	if (!strcmp(scenario, "failed-alloc"))
		return kxc_scenario_failed_alloc(run);
	if (!strcmp(scenario, "refheld-release"))
		return kxc_scenario_refheld_release(run);
	if (!strcmp(scenario, "typed-sync"))
		return kxc_scenario_typed_sync(run);
	if (!strcmp(scenario, "failed-init"))
		return kxc_scenario_failed_init(run);
	if (!strcmp(scenario, "shared-release"))
		return kxc_scenario_shared_release(run);
	if (!strcmp(scenario, "reuse-burst"))
		return kxc_scenario_reuse_burst(run);
	if (!strcmp(scenario, "rekey"))
		return kxc_scenario_rekey(run);
	if (!strcmp(scenario, "authsize"))
		return kxc_scenario_authsize(run);
	if (!strcmp(scenario, "sync-meta"))
		return kxc_scenario_sync_meta(run);
	if (!strcmp(scenario, "sync-enokey"))
		return kxc_scenario_sync_enokey(run);
	return -EINVAL;
}
