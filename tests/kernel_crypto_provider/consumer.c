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
#include <linux/slab.h>
#include <crypto/skcipher.h>

#include "fixture.h"

#define KXC_BLOCK 16
#define KXC_KEYLEN 16
#define KXC_IVLEN 16
/* Async wait sliced so STOP can abort the run. */
#define KXC_WAIT_SLICE_MS 100
#define KXC_WAIT_SLICES 100

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
	 */
	kxc_emit_terminal(op->run, op->seq, err);
	complete(&op->done);
}

static int kxc_op_prepare(struct kxc_run *run, struct kxc_op *op,
			  const char *drv_name, u64 *aseq)
{
	u8 *buf;

	memset(op, 0, sizeof(*op));
	op->run = run;
	op->tfm = crypto_alloc_skcipher(drv_name, 0, 0);
	if (IS_ERR(op->tfm))
		return PTR_ERR(op->tfm);
	*aseq = kxc_next_seq(run);
	kxc_emit_alloc(run, *aseq, drv_name,
		       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(op->tfm)));
	if (crypto_skcipher_setkey(op->tfm, kxc_key, KXC_KEYLEN))
		return -EKEYREJECTED;
	op->req = skcipher_request_alloc(op->tfm, GFP_KERNEL);
	if (!op->req)
		return -ENOMEM;
	op->page = alloc_page(GFP_KERNEL);
	if (!op->page)
		return -ENOMEM;
	buf = page_address(op->page);
	memcpy(buf, kxc_pt, KXC_BLOCK);
	sg_init_one(&op->sg, buf, KXC_BLOCK);
	skcipher_request_set_callback(op->req, 0, kxc_complete, op);
	memcpy(op->iv, kxc_iv, KXC_IVLEN);
	skcipher_request_set_crypt(op->req, &op->sg, &op->sg, KXC_BLOCK,
				   op->iv);
	init_completion(&op->done);
	op->err = -EINPROGRESS;
	return 0;
}

static void kxc_op_release(struct kxc_run *run, struct kxc_op *op, u64 aseq)
{
	skcipher_request_free(op->req);
	__free_page(op->page);
	crypto_free_skcipher(op->tfm);
	/* Fixture transforms are never shared: every free is final. */
	kxc_emit_free(run, aseq, true);
}

static int kxc_wait_done(struct kxc_run *run, struct kxc_op *op)
{
	int i;

	for (i = 0; i < KXC_WAIT_SLICES; i++) {
		if (kxc_run_stop_requested(run)) {
			/*
			 * No callback may touch op/ledger after we
			 * return: flush the driver queue first. A late
			 * terminal row still lands before DONE, and the
			 * nonzero result rejects the run honestly.
			 */
			kxc_flush_work();
			return -ECANCELED;
		}
		if (wait_for_completion_timeout(&op->done,
						msecs_to_jiffies(KXC_WAIT_SLICE_MS)))
			return op->err;
	}
	kxc_flush_work();
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

int kxc_scenario_run(struct kxc_run *run, const char *scenario)
{
	if (!strcmp(scenario, "sync-once"))
		return kxc_scenario_sync_once(run);
	if (!strcmp(scenario, "async-once"))
		return kxc_scenario_async_once(run);
	return -EINVAL;
}
