// SPDX-License-Identifier: GPL-3.0-or-later
//! Gated lifecycle capture: named profiles + raw-edge decode (T06).
//!
//! Sensor owner: [`load_lifecycle_configured`] resolves the manifest's
//! BTF ids, loads the lifecycle object, and attaches every required
//! site DISARMED (fresh `LCFG` reads zero); the caller takes its
//! pre-arm baseline, then arms via [`arm_lifecycle_config`] (M1:
//! arm-after-links — edges firing between attach and arm feed
//! `LLOSS_DISABLED`, counted, never silent), and disarms via
//! [`disarm_lifecycle_config`] before detach (flags-word flip only —
//! the chase offsets stay immutable from arm until the map dies, so a
//! hook racing the disarm never mixes valid offsets with zeroed
//! words). Any missing required
//! site — at resolve, load, or attach time — fails the whole
//! bring-up (no per-point degrade: one site alone cannot observe both
//! operations).

pub mod backend;
pub mod canary;
pub mod decode;
pub mod proc_crypto;
pub mod profile;
pub mod sensor;
pub mod tfm;
pub mod view;

use crate::attach::{OwnedLink, attach_group_tracing};
use crate::bpfloader::progload::attach_type_for_section;
use crate::bpfloader::{LoadedLifecycle, PointStatus, load_lifecycle};
use crate::btf_resolve::{
    AttachOutcome, ConfiguredError, ConfiguredPoint, resolve_lifecycle_ids,
    resolve_lifecycle_offsets, system_object,
};
use crate::kcrypto_lifecycle::profile::{
    LCFG_VALUE_LEN, LifecycleProfile, disarm_config_bytes, lifecycle_config_bytes, manifest,
    missing_required_points, verify_lifecycle_config_bytes,
};
use crate::mapops::{MapOpsError, map_lookup_bytes, map_update_bytes};
use kryprobe_core::attach::CookieAllocator;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_core::{GenerationGuard, LinkGroup};
use std::os::fd::RawFd;

/// Attached lifecycle sensor: loaded maps/programs + one tracing link
/// per required edge. Dropping detaches (RAII links) and releases the
/// maps/programs.
///
/// No `try_clone` by design (T06): the sensor has exactly one owner
/// (this struct, single-threaded drain). The live-tick handle
/// duplication (H1(b) pattern) arrives with the T08 backend wiring,
/// which restores cloning alongside its first real user.
#[derive(Debug)]
pub struct ConfiguredLifecycle {
    /// Loaded lifecycle maps + programs.
    pub loaded: LoadedLifecycle,
    /// One link per required edge as (section, link) pairs.
    pub links: Vec<(String, OwnedLink)>,
}

/// Resolve + load + attach the request-lifecycle sensor DISARMED
/// (T06 configured-combo twin; M1 arm-after-links). Returns the
/// sensor plus one [`ConfiguredPoint`] per parsed program; fails
/// unless EVERY required site attaches (all-or-nothing: partial links
/// drop with the error via RAII, so a returned error always means no
/// live sensor). The caller arms via [`arm_lifecycle_config`] after
/// its pre-arm baseline — edges firing while disarmed feed
/// `LLOSS_DISABLED`, counted, never silent.
pub fn load_lifecycle_configured(
    object_bytes: &[u8],
    token_fd: Option<RawFd>,
) -> Result<(ConfiguredLifecycle, Vec<ConfiguredPoint>), ConfiguredError> {
    let ids = resolve_lifecycle_ids().map_err(ConfiguredError::Resolve)?;
    let table = manifest(LifecycleProfile::RequestLifecycle);
    let entries: Vec<(String, u32)> = table
        .required
        .iter()
        .map(|site| (site.symbol.to_owned(), ids[site.symbol]))
        .collect();
    let (loaded, statuses) =
        load_lifecycle(object_bytes, &entries, token_fd).map_err(ConfiguredError::Load)?;
    let guard = GenerationGuard {
        generation: PlanGeneration::new(1),
    };
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let mut links: Vec<(String, OwnedLink)> = Vec::with_capacity(loaded.progs.len());
    let mut outcomes: Vec<(String, AttachOutcome)> = Vec::with_capacity(loaded.progs.len());
    for (section, prog) in &loaded.progs {
        let range = alloc
            .allocate(1)
            .map_err(|exhausted| ConfiguredError::AttachSetup {
                detail: format!("cookie range for {section}: {exhausted}"),
            })?;
        let group = LinkGroup::from_range(
            system_object(),
            ProgramId::KCryptoLifecycle,
            TargetScope::System,
            true,
            range,
        );
        let attach = attach_type_for_section(section).map(|attach_type| {
            attach_group_tracing(&group, &guard, prog, attach_type).map_err(|err| err.to_string())
        });
        match attach {
            Some(Ok(link)) => {
                links.push((section.clone(), link));
                outcomes.push((section.clone(), AttachOutcome::Attached));
            }
            Some(Err(detail)) => outcomes.push((section.clone(), AttachOutcome::Failed { detail })),
            None => outcomes.push((
                section.clone(),
                AttachOutcome::Failed {
                    detail: format!("section '{section}' is not a tracing program"),
                },
            )),
        }
    }
    let mut points = Vec::with_capacity(statuses.len());
    for status in &statuses {
        let name = match status {
            PointStatus::Loaded { name }
            | PointStatus::Missing { name }
            | PointStatus::Unsupported { name, .. } => name.clone(),
        };
        let attach = outcomes
            .iter()
            .find(|(section, _)| *section == name)
            .map(|(_, outcome)| outcome.clone());
        points.push(ConfiguredPoint {
            name,
            load: status.clone(),
            attach,
        });
    }
    let refs: Vec<(&str, &PointStatus)> = statuses
        .iter()
        .map(|st| match st {
            PointStatus::Loaded { name }
            | PointStatus::Missing { name }
            | PointStatus::Unsupported { name, .. } => (name.as_str(), st),
        })
        .collect();
    let mut failed: Vec<String> = missing_required_points(&refs);
    for (section, _) in &loaded.progs {
        let attached = outcomes
            .iter()
            .any(|(s, o)| s == section && matches!(o, AttachOutcome::Attached));
        if !attached && !failed.contains(section) {
            failed.push(section.clone());
        }
    }
    if !failed.is_empty() {
        // All-or-nothing: `loaded` + `links` drop here, so no live
        // sensor survives a partial bring-up (`NoPointAttached` is
        // literally true post-cleanup; `points` carries the per-edge
        // diagnosis).
        drop(links);
        drop(loaded);
        return Err(ConfiguredError::NoPointAttached { points });
    }
    Ok((ConfiguredLifecycle { loaded, links }, points))
}

/// Arm the sensor (M1: after links attach, after the pre-arm
/// baseline): resolve the BTF chase offsets, write `LCFG` key 0, and
/// read the full 64-byte value back. Unresolvable offsets refuse the
/// arm BEFORE any write (T07: the transform programs chase through
/// these words — zeroed guesses would mis-chase). Any readback
/// mismatch (unwritten/zeroed map, short write, drifted word, offset
/// corruption) fails closed instead of claiming an armed sensor. The
/// readback proves the final value only — edges straddling the arm
/// land in `LLOSS_DISABLED` or accepted, counted either way, never
/// certified. Returns the resolved offsets: the tracker normalizes
/// frontend pointers with the same `sk_base` word the BPF chase
/// adds, so both sides of the join resolve per kernel, never from a
/// hardcoded layout (T07.2d: `crypto_skcipher.base` sits at 8 on
/// 64-bit — `reqsize` + alignment padding — not 4).
/// D3: the arm resolves ONLY the lifecycle set (shape-validated);
/// the aggregate's legacy fields can neither arm nor refuse us.
pub fn arm_lifecycle_config(
    loaded: &LoadedLifecycle,
) -> Result<crate::btf_resolve::LifecycleOffsets, ConfiguredError> {
    let offsets = resolve_lifecycle_offsets().map_err(ConfiguredError::Resolve)?;
    let bytes = lifecycle_config_bytes(&offsets);
    map_update_bytes(
        &loaded.maps.config,
        &0u32.to_le_bytes(),
        &bytes,
        "lifecycle_configured/lcfg",
    )
    .map_err(ConfiguredError::Configure)?;
    // SAFETY: `LCFG_VALUE_LEN` equals the manifest `LCFG.value_size`
    // (pinned by `f1_lcfg_value_len_matches_manifest`); the object
    // parse refuses any other width and instantiate creates the map
    // from the parsed dims, so the kernel writes exactly the
    // allocated bytes — never the 8-byte `map_lookup` helper
    // (round-1 sol-M1/astra-M1: that was a stack overwrite).
    let got = unsafe {
        map_lookup_bytes(
            &loaded.maps.config,
            &0u32.to_le_bytes(),
            LCFG_VALUE_LEN,
            "lifecycle_configured/lcfg-verify",
        )
    }
    .map_err(ConfiguredError::Configure)?;
    verify_lifecycle_config_bytes(&got, &bytes).map_err(|reason| {
        ConfiguredError::Configure(MapOpsError::ConfigRejected {
            stage: "lifecycle_configured/lcfg-verify".to_owned(),
            detail: format!("{reason:?}"),
        })
    })?;
    Ok(offsets)
}

/// Disarm the sensor (M1: before links detach): read `LCFG` key 0,
/// write it back with ONLY the flags word set ([`disarm_config_bytes`]),
/// and read the full 64-byte value back. The chase offsets are NEVER
/// rewritten by the disarm (D1: whole-value zeroing let a racing hook
/// mix valid offsets with zeroed words — a one-word flags flip keeps
/// every other word identical old-vs-new, so each racing aligned-word
/// read observes the armed value or a gate-closed value, never a
/// mixture). A readback that differs from the written bytes fails —
/// the caller still detaches (a detached sensor fires nothing, so the
/// config value is moot), but the error attests the disarm was never
/// proven. Like the arm, the readback proves the final value only.
pub fn disarm_lifecycle_config(loaded: &LoadedLifecycle) -> Result<(), ConfiguredError> {
    // SAFETY: same pinned-width argument as the arm readback above.
    let current = unsafe {
        map_lookup_bytes(
            &loaded.maps.config,
            &0u32.to_le_bytes(),
            LCFG_VALUE_LEN,
            "lifecycle_disarm/lcfg-read",
        )
    }
    .map_err(ConfiguredError::Configure)?;
    if current.len() != LCFG_VALUE_LEN {
        return Err(ConfiguredError::Configure(MapOpsError::ConfigRejected {
            stage: "lifecycle_disarm/lcfg-read".to_owned(),
            detail: format!(
                "disarm pre-read is {} bytes, want {LCFG_VALUE_LEN}",
                current.len()
            ),
        }));
    }
    let mut live = [0u8; LCFG_VALUE_LEN];
    live.copy_from_slice(&current);
    let disarmed = disarm_config_bytes(&live);
    map_update_bytes(
        &loaded.maps.config,
        &0u32.to_le_bytes(),
        &disarmed,
        "lifecycle_disarm/lcfg",
    )
    .map_err(ConfiguredError::Configure)?;
    // SAFETY: same pinned-width argument as the arm readback above.
    let got = unsafe {
        map_lookup_bytes(
            &loaded.maps.config,
            &0u32.to_le_bytes(),
            LCFG_VALUE_LEN,
            "lifecycle_disarm/lcfg-verify",
        )
    }
    .map_err(ConfiguredError::Configure)?;
    if got.len() != LCFG_VALUE_LEN || got != disarmed {
        return Err(ConfiguredError::Configure(MapOpsError::ConfigRejected {
            stage: "lifecycle_disarm/lcfg-verify".to_owned(),
            detail: "disarm readback differs from written bytes".to_owned(),
        }));
    }
    Ok(())
}
