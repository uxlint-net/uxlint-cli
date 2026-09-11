//! Gate on the TAB-WALK focus probe in `src/passes.rs` — the measurement behind `state-focus-visible`.
//!
//! Reported from the field on 2026-08-31, as two symptoms of two causes:
//!   * the finding fired naming an EMPTY element (`"" has no visible focus indicator`), which leaves
//!     a reader with nothing to go and look at (the server side of that is `focus_target_name`);
//!   * and it VANISHED on the very next run of the identical route with no code change between —
//!     "a finding that appears and disappears across consecutive runs of unchanged code trains people
//!     to ignore the whole report."
//!
//! The second is a race, and this file pins its fix. `getComputedStyle` on an element whose focus ring
//! is mid-transition returns the INTERPOLATED value, so reading straight after `blur()` samples
//! somewhere between the two states — and which side it lands on depends on how busy the machine was.
//! The probe therefore suppresses transition/animation for the two reads, forces a reflow between
//! them, and restores the inline styles afterwards. Asserted against the shipped source, because the
//! failure this prevents is invisible in any single run.

const PROBE: &str = include_str!("../src/passes.rs");

/// The probe body: from `document.activeElement` to the JSON it returns.
fn focus_probe() -> &'static str {
    let start = PROBE
        .find(
            "  const el = document.activeElement;\n  if (!el || el === document.body) return null;",
        )
        .expect("the tab-walk focus probe is still in passes.rs");
    let end = PROBE[start..].find("})()\"##,").expect("probe end") + start;
    &PROBE[start..end]
}

#[test]
fn the_focus_comparison_measures_settled_styles_not_a_transition() {
    let p = focus_probe();
    assert!(
        p.contains("el.style.transition = 'none'") && p.contains("el.style.animation = 'none'"),
        "both must be suppressed, or the comparison samples an animating value and flips between runs"
    );
    // Restored on every path, including a throw — the probe must leave the page as it found it.
    assert!(
        p.contains("} finally {")
            && p.contains("el.style.transition = prevT")
            && p.contains("el.style.animation = prevA"),
        "the inline styles must be restored in a finally, not on the happy path only"
    );
    // A reflow between suppression and the first read, and between blur and the second — without
    // them the suppression hasn't applied and the blurred read is the stale focused one.
    assert_eq!(
        p.matches("el.getBoundingClientRect(); //").count(),
        2,
        "one forced reflow before each read"
    );
    // Order is the whole point: suppress, read focused, blur, read blurred, refocus.
    let at = |needle: &str| {
        p.find(needle)
            .unwrap_or_else(|| panic!("missing: {needle}"))
    };
    assert!(at("el.style.transition = 'none'") < at("focused = pick(el)"));
    assert!(at("focused = pick(el)") < at("el.blur()"));
    assert!(at("el.blur()") < at("blurred = pick(el)"));
    assert!(at("blurred = pick(el)") < at("el.focus()"));
}

#[test]
fn the_probe_looks_past_aria_label_for_a_name() {
    // The naming half. An icon button with only a `title`, a bare input with only a `placeholder`,
    // and an image button are all nameable — and every name the probe finds is one finding the
    // server doesn't have to drop for being unactionable.
    let p = focus_probe();
    for attr in [
        "aria-label",
        "title",
        "textContent",
        "placeholder",
        "img[alt]",
    ] {
        assert!(p.contains(attr), "the name walk should consider {attr}");
    }
    // The key carries the id, so an unnamed-but-identifiable element still has somewhere to point.
    assert!(
        p.contains("el.id ? '#' + el.id : ''"),
        "an element with an id is findable even with no accessible name"
    );
}
