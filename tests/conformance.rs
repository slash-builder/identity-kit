//! Identity Kit's first CI-enforced conformance gate.
//!
//! Imports the frozen `spec_kit::conformance::{Case, run_suite}` harness
//! (the `slashbuilder-spec-kit` crate on crates.io) and exercises identity-kit's own invariants:
//! `Capabilities` scope inclusion, `ServicePrincipal::has` delegating to
//! it, principal-id stability/uniqueness, and the "no persisted
//! tier/circle/role-as-trust field" hard constraint from `src/authz.rs`.
//! This CI-locks the linchpin kit's capability/principal invariants.

use identity_kit::authz::{Capabilities, PrincipalId, Scope, ServicePrincipal};
use serde_json::Value;
use spec_kit::conformance::{run_suite, Case};

fn scope(s: &str) -> Scope {
    Scope(s.to_string())
}

/// Case 1: `Capabilities::includes` reports true for a scope it holds and
/// false for one it doesn't.
struct CapabilityInclusion;
impl Case for CapabilityInclusion {
    fn name(&self) -> &str {
        "identity-kit::Capabilities::includes reports held vs. absent scopes correctly"
    }
    fn run(&self) -> Result<(), String> {
        let a = scope("read:account");
        let b = scope("write:family");
        let c = scope("admin:everything");

        let caps = Capabilities::new(vec![a.clone(), b.clone()]);

        if !caps.includes(&a) {
            return Err("Capabilities::includes(A) should be true when A is held".into());
        }
        if caps.includes(&c) {
            return Err("Capabilities::includes(C) should be false when C is not held".into());
        }
        Ok(())
    }
}

/// Case 2: `ServicePrincipal::has` delegates to `Capabilities::includes`
/// rather than re-implementing its own check.
struct PrincipalHasDelegation;
impl Case for PrincipalHasDelegation {
    fn name(&self) -> &str {
        "identity-kit::ServicePrincipal::has delegates to Capabilities::includes"
    }
    fn run(&self) -> Result<(), String> {
        let a = scope("read:account");
        let b = scope("write:family");
        let c = scope("admin:everything");

        let caps = Capabilities::new(vec![a.clone(), b.clone()]);
        let principal = ServicePrincipal::new(None, caps);

        if !principal.has(&a) {
            return Err(
                "ServicePrincipal::has(A) should be true when the held capabilities include A"
                    .into(),
            );
        }
        if principal.has(&c) {
            return Err("ServicePrincipal::has(C) should be false when the held capabilities do not include C".into());
        }
        Ok(())
    }
}

/// Case 3: principal identity is stable when rehydrated from a known
/// `PrincipalId`, and two freshly generated principals never collide.
struct PrincipalIdentityStability;
impl Case for PrincipalIdentityStability {
    fn name(&self) -> &str {
        "identity-kit::PrincipalId is stable on rehydration and distinct across fresh principals"
    }
    fn run(&self) -> Result<(), String> {
        // Rehydrating a principal from a known id must preserve that id.
        let known_id = PrincipalId::new();
        let rehydrated = ServicePrincipal::with_id(known_id, None, Capabilities::default());
        if rehydrated.id() != known_id {
            return Err(
                "ServicePrincipal::with_id did not preserve the supplied PrincipalId".into(),
            );
        }

        // Two independently constructed principals must not share an id.
        let p1 = ServicePrincipal::new(None, Capabilities::default());
        let p2 = ServicePrincipal::new(None, Capabilities::default());
        if p1.id() == p2.id() {
            return Err("two freshly constructed ServicePrincipals produced the same id".into());
        }
        Ok(())
    }
}

/// Case 4: the no-tier invariant, checked structurally at the conformance
/// layer (not just via the compile-time destructuring guard in
/// `src/authz.rs`'s unit tests). The serialized wire form of a
/// `ServicePrincipal` must carry exactly `id`, `device`, and
/// `capabilities` — no `tier`, `circle`, `role`, or other trust-as-role
/// field.
struct NoTierInvariant;
impl Case for NoTierInvariant {
    fn name(&self) -> &str {
        "identity-kit::ServicePrincipal's serialized form carries no tier/circle/role field"
    }
    fn run(&self) -> Result<(), String> {
        let caps = Capabilities::new(vec![scope("pair:device")]);
        let principal = ServicePrincipal::new(None, caps);

        let json = serde_json::to_value(&principal).map_err(|e| e.to_string())?;
        let obj = match &json {
            Value::Object(map) => map,
            other => return Err(format!("expected a JSON object, got {other:?}")),
        };

        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let expected = vec!["capabilities", "device", "id"];
        if keys != expected {
            return Err(format!(
                "expected exactly {expected:?} as top-level fields, found {keys:?}"
            ));
        }

        for forbidden in ["tier", "circle", "role", "trust", "trust_tier"] {
            if obj.contains_key(forbidden) {
                return Err(format!(
                    "serialized ServicePrincipal must not carry a `{forbidden}` field"
                ));
            }
        }

        // And it must round-trip: the wire form is a faithful encoding,
        // not a lossy projection that happens to omit the forbidden keys.
        let back: ServicePrincipal = serde_json::from_value(json).map_err(|e| e.to_string())?;
        if back.id() != principal.id() {
            return Err("ServicePrincipal did not round-trip through serde intact".into());
        }
        Ok(())
    }
}

#[test]
fn identity_kit_conformance_suite() {
    let cases: Vec<Box<dyn Case>> = vec![
        Box::new(CapabilityInclusion),
        Box::new(PrincipalHasDelegation),
        Box::new(PrincipalIdentityStability),
        Box::new(NoTierInvariant),
    ];
    let case_refs: Vec<&dyn Case> = cases.iter().map(|c| c.as_ref()).collect();
    let report = run_suite(&case_refs);

    for (name, err) in &report.failed {
        eprintln!("FAILED conformance case {name}: {err}");
    }
    assert!(
        report.is_success(),
        "{} of {} conformance cases failed: {:?}",
        report.failed.len(),
        report.total(),
        report.failed
    );
}
