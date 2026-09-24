/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kcrypto_fixture shared declarations (TEST ONLY, see README.md).
 *
 * Ledger row contract (JSONL, parsed by testkit
 * kernel_crypto_ledger; unknown fields ignored):
 *   alloc:    {"v":1,"run":R,"seq":N,"phase":"alloc","req":R,"drv":D,...}
 *   submit:   {"v":1,"run":R,"seq":N,"phase":"submit","op":O,"len":L,...}
 *   return:   {"v":1,"run":R,"seq":N,"phase":"return","errno":E,...}
 *   progress: {"v":1,"run":R,"seq":N,"phase":"progress","errno":E,...}
 *   terminal: {"v":1,"run":R,"seq":N,"phase":"terminal","errno":E,...}
 *   free:     {"v":1,"run":R,"seq":N,"phase":"free","final":B,...}
 *   done:     {"v":1,"run":R,"phase":"done","fixture_result":F,
 *              "overflow":C,...}
 * Every row also carries "ts" (ktime ns) and, where meaningful,
 * "cpu". All interpolated strings are validated [A-Za-z0-9_-]
 * (run_id at PREPARE, suffix at load, the rest are constants), so
 * no JSON escaping is needed; validation failure rejects the input,
 * never emits a lying row.
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
void kxc_ledger_reset(void);
u64 kxc_next_seq(struct kxc_run *run);
int kxc_run_begin(struct kxc_run *run, const char *id,
		  const char *scenario, u64 seed);
void kxc_run_finish(struct kxc_run *run, int result);
bool kxc_run_stop_requested(struct kxc_run *run);
void kxc_run_request_stop(struct kxc_run *run);
const char *kxc_sync_driver_name(void);
const char *kxc_async_driver_name(void);
void kxc_flush_work(void);

/* consumer.c: scenarios. */
int kxc_scenario_run(struct kxc_run *run, const char *scenario);

#endif /* KXC_FIXTURE_H */
