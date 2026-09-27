/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kcrypto_fixture shared declarations (TEST ONLY, see README.md).
 *
 * Ledger row contract (JSONL, parsed by testkit
 * kernel_crypto_ledger; unknown fields ignored):
 *   alloc:    {"v":1,"run":R,"seq":N,"phase":"alloc","req":R,"drv":D,
 *              "type":T,"mask":M,...}
 *   submit:   {"v":1,"run":R,"seq":N,"phase":"submit","op":O,"len":L,
 *              "flags":F,...} (F: request base.flags at submit)
 *   return:   {"v":1,"run":R,"seq":N,"phase":"return","errno":E,...,
 *              "entries":N}
 *     ("entries": provider-body entries at emit time — P3r marker,
 *     skcipher only; extra field, unknown-field-tolerant readers
 *     ignore it)
 *   progress: {"v":1,"run":R,"seq":N,"phase":"progress","errno":E,...}
 *     (T09: EITHER a waiter-side in-flight marker (delayed
 *     scenario) OR a kernel backlog-progress callback
 *     (kxc_complete(-EINPROGRESS) under the held burst — errno
 *     -EINPROGRESS, always before that seq's terminal))
 *   terminal: {"v":1,"run":R,"seq":N,"phase":"terminal","errno":E,...}
 *   config:   {"v":1,"run":R,"seq":N,"phase":"config","op":O,
 *              "errno":E,"len":L,...}
 *     (metadata-only configuration truth: op is setkey or
 *     setauthsize, errno the native result, len the key/authsize
 *     length offered — lengths only, never key/tag/IV bytes)
 *   free:     {"v":1,"run":R,"seq":N,"phase":"free","final":B,...}
 *     (one row per put: a shared transform lands several; the
 *     last final flag decides finality)
 *   done:     {"v":1,"run":R,"phase":"done","fixture_result":F,
 *              "overflow":C,"entries":N,...}
 * Every row also carries "ts" (ktime ns) and, where meaningful,
 * "cpu". All interpolated strings are validated [A-Za-z0-9_-]
 * (run_id at PREPARE, suffix at load, the rest are constants), so
 * no JSON escaping is needed; validation failure rejects the input,
 * never emits a lying row.
 *
 * Structural strictness (enforced by testkit kernel_crypto_ledger):
 * every request needs submit, return and terminal rows; op/req/drv
 * are non-empty; return/progress/terminal carry errno; free
 * carries final (repeatable per seq, last wins); config carries
 * op/errno/len (repeatable per seq, requires a prior alloc);
 * alloc carries u32 type/mask provenance; DONE carries overflow;
 * no row follows DONE.
 */
#ifndef KXC_FIXTURE_H
#define KXC_FIXTURE_H

#include <linux/types.h>

#define KXC_RUN_ID_MAX 64
#define KXC_SCENARIO_MAX 32
#define KXC_SUFFIX_MAX 32
#define KXC_DRV_NAME_MAX 96

/* driver.cra_name shared by both fixture drivers. */
#define KXC_GENERIC_NAME "kxcipher"

/* Widest tag any scenario selects (16): the consumer sizes AEAD
 * dst spans with this headroom (an encrypt writes cryptlen +
 * tag), and the provider rejects anything wider. */
#define KXC_AEAD_MAXAUTHSIZE 16

/* Ledger ring capacity. */
#define KXC_ROW_LEN 512
#define KXC_ROWS_MAX 4096

/* Control input bound (matrix: versioned, length-bounded). */
#define KXC_CMD_MAX 256

struct kxc_run {
	char id[KXC_RUN_ID_MAX + 1];
	char scenario[KXC_SCENARIO_MAX + 1];
	u64 seed;
	atomic64_t seq;
	bool prepared;
	bool done;
	int fixture_result;
	bool stop;
};

/* provider.c: ledger + debugfs + drivers. */
int kxc_ledger_emit(const char *fmt, ...) __printf(1, 2);
u64 kxc_ledger_dropped(void);
u64 kxc_crypt_entries_count(void);
void kxc_ledger_reset(void);
u64 kxc_next_seq(struct kxc_run *run);
int kxc_run_begin(struct kxc_run *run, const char *id,
		  const char *scenario, u64 seed);
void kxc_run_finish(struct kxc_run *run, int result);
bool kxc_run_stop_requested(struct kxc_run *run);
void kxc_run_request_stop(struct kxc_run *run);
const char *kxc_sync_driver_name(void);
const char *kxc_async_driver_name(void);
const char *kxc_fail_driver_name(void);
const char *kxc_aead_driver_name(void);
const char *kxc_aead_async_driver_name(void);
void kxc_flush_work(void);
void kxc_drain_kick(void);
void kxc_set_submit_hold(bool hold);
void kxc_set_delay_ms(int ms);
void kxc_set_inline_once(bool once);

/* consumer.c: scenarios. */
int kxc_scenario_run(struct kxc_run *run, const char *scenario);

#endif /* KXC_FIXTURE_H */
