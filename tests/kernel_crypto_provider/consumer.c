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
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
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
			   const char *drv)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"alloc\","
		"\"req\":\"%s\",\"drv\":\"%s\",\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, req_name, drv, ktime_get_ns(),
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
			    unsigned int len)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"submit\","
		"\"op\":\"%s\",\"len\":%u,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, op, len, ktime_get_ns(), smp_processor_id());
}

static void kxc_emit_return(struct kxc_run *run, u64 seq, int errno_)
{
	kxc_ledger_emit(
		"{\"v\":1,\"run\":\"%s\",\"seq\":%llu,\"phase\":\"return\","
		"\"errno\":%d,\"ts\":%llu,\"cpu\":%u}",
		run->id, seq, errno_, ktime_get_ns(), smp_processor_id());
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

static int kxc_tfm_acquire(struct kxc_run *run, const char *req_name,
			   struct crypto_skcipher **tfm, u64 *aseq)
{
	struct crypto_skcipher *t;

	t = crypto_alloc_skcipher(req_name, 0, 0);
	if (IS_ERR(t))
		return PTR_ERR(t);
	*aseq = kxc_next_seq(run);
	kxc_emit_alloc(run, *aseq, req_name,
		       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(t)));
	if (crypto_skcipher_setkey(t, kxc_key, KXC_KEYLEN)) {
		kxc_tfm_release(run, t, *aseq);
		return -EKEYREJECTED;
	}
	*tfm = t;
	return 0;
}

static void kxc_tfm_release(struct kxc_run *run, struct crypto_skcipher *tfm,
			    u64 aseq)
{
	crypto_free_skcipher(tfm);
	/* Fixture transforms are never shared: every free is final. */
	kxc_emit_free(run, aseq, true);
}

static int kxc_req_setup(struct kxc_run *run, struct crypto_skcipher *tfm,
			 struct kxc_op *op, u32 cb_flags)
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
	memcpy(buf, kxc_pt, KXC_BLOCK);
	sg_init_one(&op->sg, buf, KXC_BLOCK);
	skcipher_request_set_callback(op->req, cb_flags, kxc_complete, op);
	memcpy(op->iv, kxc_iv, KXC_IVLEN);
	skcipher_request_set_crypt(op->req, &op->sg, &op->sg, KXC_BLOCK,
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
	err = kxc_req_setup(run, tfm, op, 0);
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
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK);
	err = crypto_skcipher_encrypt(op.req);
	kxc_emit_return(run, seq, err);
	/* A synchronous return IS the terminal result: record both rows. */
	kxc_emit_terminal(run, seq, err);
	if (err)
		goto out;
	memcpy(op.iv, kxc_iv, KXC_IVLEN);
	skcipher_request_set_crypt(op.req, &op.sg, &op.sg, KXC_BLOCK, op.iv);
	seq = kxc_next_seq(run);
	kxc_emit_submit(run, seq, "decrypt", KXC_BLOCK);
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
	kxc_emit_submit(run, seq, "encrypt", KXC_BLOCK);
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
	kxc_emit_submit(run, seq, "encrypt-delayed", KXC_BLOCK);
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
				    CRYPTO_TFM_REQ_MAY_BACKLOG);
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

		kxc_emit_submit(run, seqs[i], "encrypt-burst", KXC_BLOCK);
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
	kxc_emit_submit(run, seq, "encrypt-early", KXC_BLOCK);
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
	kxc_emit_submit(run, seq, "encrypt-exact", KXC_BLOCK);
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
	kxc_emit_submit(run, seq, "alloc-probe", 0);
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
	return -EINVAL;
}
