// SPDX-License-Identifier: GPL-3.0-or-later
//! Gated lifecycle capture: named profiles + raw-edge decode (T06).
//!
//! Sensor owner: [`load_lifecycle_configured`] resolves the manifest's
//! BTF ids, loads the lifecycle object, writes + verifies `LCFG`, and
//! attaches every required edge. Any missing required edge — at
//! resolve, load, configure, or attach time — fails the whole
//! bring-up (no per-point degrade: unpaired edges cannot pair submit
//! with result).

pub mod backend;
pub mod canary;
pub mod decode;
pub mod profile;
pub mod sensor;

use crate::attach::{OwnedLink, attach_group_tracing};
use crate::bpfloader::progload::attach_type_for_section;
use crate::bpfloader::{LoadedLifecycle, PointStatus, load_lifecycle};
use crate::btf_resolve::{
    AttachOutcome, ConfiguredError, ConfiguredPoint, resolve_lifecycle_ids, system_object,
};
use crate::kcrypto_lifecycle::profile::{
    LCFG_VALUE_LEN, LifecycleProfile, lifecycle_config_bytes, manifest, missing_required_points,
    verify_lifecycle_config_bytes,
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

/// Resolve + load + configure + attach the request-lifecycle sensor
/// (T06 configured-combo twin). Returns the sensor plus one
/// [`ConfiguredPoint`] per parsed program; fails unless EVERY
/// required edge attaches (all-or-nothing: partial links drop with
/// the error via RAII, so a returned error always means no live
/// sensor).
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
    write_lifecycle_config(&loaded)?;
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

/// Write `LCFG` key 0 and read the full 64-byte value back: any
/// mismatch (unwritten/zeroed map, short write, drifted word) fails
/// closed instead of arming a disarmed sensor.
fn write_lifecycle_config(loaded: &LoadedLifecycle) -> Result<(), ConfiguredError> {
    let bytes = lifecycle_config_bytes();
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
    verify_lifecycle_config_bytes(&got).map_err(|reason| {
        ConfiguredError::Configure(MapOpsError::ConfigRejected {
            stage: "lifecycle_configured/lcfg-verify".to_owned(),
            detail: format!("{reason:?}"),
        })
    })
}
