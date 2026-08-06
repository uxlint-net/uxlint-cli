//! Proactive UI best-practice guidance, served over MCP so a coding agent can build it right the
//! first time instead of learning from audit findings. Each topic distils the principle behind
//! uxlint's lint corpus into idiomatic, DRY, testable patterns, and names the rule that will catch
//! a miss — so "read the guidance, build to it, then `audit_url` to confirm" is a tight loop.
//!
//! Deliberately terse: the caller is an intelligent model that knows general UX. We supply only what
//! it can't derive without having run the site — the CALIBRATED bars (px, rem, ratios, counts), the
//! DRY/idiom, and the RULE NAME that catches each miss — not a UX explainer.

/// One-line index of every topic, shown when no topic (or an unknown one) is asked for.
const INDEX: &str = "\
uxlint UI guidance — pass `topic` to get the detail. Topics:
  layout        one width scale, aligned edges, no layout shift
  forms         single column, labels above, real inputs
  lists         pagination by length, whole-row targets, row actions
  navigation    tabs/radiogroup vs buttons, active state, primary nav
  components    DRY, tokenised, testable, accessible by construction
  performance   window long lists, reserve space, size media
  accessibility semantics, names, focus, target size
  content       words are UI — active voice, honest labels, useful empty/error states
Pass topic=\"all\" for everything.";

const LAYOUT: &str = r#"## Layout — consistency & stability

One column, one rhythm: stacked blocks share a width and an edge; space/size come from a scale.

DO
- ONE shared max-width for stacked panels/sections (one container/token) so left AND right edges
  line up down the page. [rule: panel-widths]
- Differ in width only for panels side-by-side in a ROW spanning the content area — varied widths in
  a vertical stack read as a ragged staircase.
- ONE spacing/size scale (e.g. 4px steps) for gaps, padding, widths; repeated components identical
  width. [rule: inconsistent-widths, layout-consistency]
- Reserve space for async content: width/height on images/embeds, skeletons sized to final content,
  nothing inserted above the fold. [rule: layout-shift]
- Reserve the scrollbar gutter (`scrollbar-gutter: stable` on root) so scrolling vs non-scrolling
  pages don't shift the centred layout sideways. [rule: scrollbar-gutter-shift]

DON'T
- One-off max-w-* / width per block. Full-bleed one thing and constrain the next.
- Centre a max-width box with text-align instead of margins (the box hugs one side). [off-center-content]

Testable: every top-level block shares one computed width (or is a deliberate row); CLS < 0.1; no
horizontal shift when a scrollbar appears."#;

const FORMS: &str = r#"## Forms — one column, labelled, honest inputs

A form is a single vertical column of labelled fields; each field is one row.

DO
- Stack fields in one column, a visible <label> ABOVE each input. [rule: multi-column-form,
  inline-form-fields, unlabelled-field]
- Side-by-side fields only as a rare, deliberate, EQUAL-width pair (city / postcode).
- Right input types: type=email/tel/number, autocomplete, inputmode; a real <select> for long
  choice lists. [rule: input-type-mismatch, autocomplete-missing, placeholder-as-label]
- Submit on its own row, labelled by the action ("Save credential", not "Submit"). [rule: generic-submit-label]
- Constrain to a readable measure (~28–36rem) — then EVERY block in that view matches it.

DON'T
- Pack a select + inputs + button onto one wrapping row at mismatched widths. [inline-form-fields]
- Use the placeholder as the only label. [placeholder-as-label]

Testable: each field on its own row with an associated label; tab order top-to-bottom; form width
matches its sibling panels."#;

const LISTS: &str = r#"## Lists & tables — length, targets, actions

A list you open should be easy to scan, forgiving to click, and never an endless scroll.

DO
- Whole row is the target via the stretched-link pattern: a positioned link filling the row
  (`position:absolute; inset:0`), row actions layered above (`position:relative; z-index:1`) —
  one big target, not a tiny date link. [rule: list-row-click-target]
- Give data rows the full width so each fits one line; reserve narrow measures for prose/forms.
- Paginate/window by LENGTH not item count: past ~2 screens, page / "load more" / virtualise (keep
  a screenful in the DOM). [rule: list-unpaginated, list-no-infinite-scroll]
- Offer search/filter once a collection exceeds a screenful. [rule: searchability]
- Give a managed collection a "New/Add" affordance. [rule: collection-no-create]

DON'T
- Make only a sub-element of a tall row clickable.
- Render hundreds of rows on every load.

Testable: clicking anywhere on a row (except an action) navigates; tallest list under ~2 screens or
paged/virtualised; a filter exists past one screenful."#;

const NAVIGATION: &str = r#"## Navigation & selection

Mutually-exclusive choices are a selector, not a pile of buttons; nav is consistent and shows where
you are.

DO
- "Pick one of N" → a real selector: tabs (role=tablist / role=tab + aria-selected) or a radiogroup,
  or a <select> when the list is long. Style the active one distinctly. [rule: select-buttons-not-tabs]
- Segmented controls: same HEIGHT, widths auto-size to content so no label wraps. [rule:
  control-group-uneven, unwanted-wrap]
- Primary nav consistent across pages; mark the current item (aria-current="page"). [rule:
  consistent-navigation, nav-content-static]
- Cap the primary nav at ~7±2 destinations; push utility/settings to a secondary spot. [rule:
  nav-overload, settings-in-primary-nav]

DON'T
- Build a tab/segmented control from bare <button>s with no roles (screen readers hear N buttons,
  no arrow-nav). [select-buttons-not-tabs]
- Make two nav items render the identical page. [nav-content-static]

Testable: a single-select group exposes role=tablist/radiogroup with one aria-selected/checked; the
active nav item is marked; segments equal height."#;

const COMPONENTS: &str = r#"## Components — DRY, tokenised, testable

Don't hand-roll the same widget twice. Encode each pattern ONCE as a reusable component with clear
props; consistency and testability then follow.

DO
- One reusable component per pattern (Panel, ListRow, Tabs, Field, LabelEditor), reused. A repeated
  card/row = one component, one width, one behaviour. [rule: inconsistent-widths, panel-widths,
  duplicate-styles]
- Drive colour/spacing/radius/width from design TOKENS (CSS vars/theme), never per-instance literals.
  One accent, one radius scale, one type scale. [rule: radius-inconsistency, type-scale,
  accent-collision, duplicate-styles]
- Accessible BY CONSTRUCTION: Tabs emits the roles, Field renders its label, ListRow stretches its
  link. The right thing is the default.
- Each component: a small explicit prop API + a test asserting its role/label/target exist.

DON'T
- Copy-paste a card's markup with tweaked widths/margins. [duplicate-styles]
- Inline styles / utility soup re-implementing a token. [inline-css, duplicate-styles]

Testable: one implementation per pattern (grep); instances differ only by data/props; tokens, not
literals, carry visual values."#;

const PERFORMANCE: &str = r#"## Performance & perceived speed

Keep the DOM small, reserve space, never make the user wait without feedback.

DO
- Window/virtualise long lists (only a screenful in the DOM); paginate/load-more the rest. [rule:
  list-unpaginated, dom-size]
- Reserve space for anything async (image width+height, sized skeletons) to avoid shift as data
  lands. [rule: layout-shift]
- Intrinsic dimensions + right-sized images (no 2000px into a 200px slot); lazy-load below the fold.
  [rule: image-overweight, image-too-small]
- Feedback within a frame for any action >~200ms (pending/disabled, skeleton). [rule:
  action-no-feedback, pending-state-missing, slow-network-no-feedback]
- Prevent font FOUT/CLS with font-display + preload. [rule: font-flash]

DON'T
- Append forever on scroll while keeping every node.
- Block first paint on data the shell doesn't need.

Testable: DOM node count stays bounded as data grows; CLS < 0.1; interactions show feedback within a
frame or two."#;

const ACCESSIBILITY: &str = r#"## Accessibility — semantics first

Right element, given a name, reachable. Most a11y wins are just correct HTML.

DO
- Native elements: <button> for actions, <a href> to navigate, <label> for fields, <nav>, <main>,
  headings in order. [rule: a-vs-button-misuse, clickable-div, semantic-poverty, heading-order-skip,
  main-landmark]
- Every control an accessible name (visible label, aria-label, or an svg <title> for icon-only and
  charts). [rule: icon-label, unlabelled-field, unlabeled-viz]
- Target size ≥ 24–44px; prefer the whole row over a tiny link. [rule: tap-target, thumb-reach,
  list-row-click-target]
- State visible AND programmatic: focus-visible rings, aria-selected/checked/current, a real focus
  order. [rule: state-focus-visible, focus-order-illogical, disclosure-state]
- Never signal meaning by colour alone. [rule: link-color-only, false-affordance-colour]

DON'T
- Click handlers on <div>s, or interactive controls nested in an <a>. [clickable-div]
- The only label hidden in a placeholder. [placeholder-as-label]

Testable: every interactive element has a role and an accessible name; keyboard reaches and operates
everything; text contrast ≥ 4.5:1."#;

const CONTENT: &str = r#"## Content & copy — words are UI

Words help someone act, not decorate. Every label, message, and empty state is design material.

DO
- Write from the user's side: name things by what people control ("Notifications", not "Webhook
  config"). Specific beats clever.
- Use active voice, say exactly what happens: a control names its action ("Save changes", not "Submit")
  and KEEPS that name through the flow — a "Publish" button lands a "Published" toast. [rule:
  generic-submit-label, duplicate-cta]
- Links/buttons describe their destination or action; never "click here" / "learn more". [rule:
  vague-link-text]
- Show, don't tell: back each claim with proof (a number, benchmark, before/after, demo); cut filler
  (delve/leverage/seamless), hedges, "not just X, Y". [rule: show-dont-tell, prose-slop]
- Empty/error states as DIRECTION: an empty screen names what will appear + offers the first action;
  an error says what broke and how to fix it, in the interface's voice. [rule: empty-state-dead]
- Real content: no lorem/placeholder or dead links in prod; keep dated copy current. [rule:
  placeholder-content-live, placeholder-link, stale-copyright-year]

DON'T
- Sell instead of explain, stack adjectives, or write "Submit" / "click here". [prose-slop, vague-link-text]
- Rename an action mid-flow — button and confirmation must use the same word. [duplicate-cta]
- Leave an empty state blank or an error vague. [empty-state-dead]

Testable: each action label matches the wording of its own confirmation; no "submit / click here /
learn more"; every empty and error state names a next step; no lorem/placeholder or dead links in prod."#;

/// Return the guidance for `topic`. Unknown/empty → the index; "all" → everything.
pub(crate) fn guidance(topic: &str) -> String {
    let t = topic.trim().to_lowercase();
    let section = |s: &str| format!("{s}\n");
    match t.as_str() {
        "layout" => section(LAYOUT),
        "forms" | "form" => section(FORMS),
        "lists" | "list" | "tables" | "table" => section(LISTS),
        "navigation" | "nav" | "tabs" => section(NAVIGATION),
        "components" | "component" | "dry" => section(COMPONENTS),
        "performance" | "perf" => section(PERFORMANCE),
        "accessibility" | "a11y" => section(ACCESSIBILITY),
        "content" | "copy" | "writing" | "microcopy" | "words" | "voice" => section(CONTENT),
        "all" | "*" => [
            INDEX,
            LAYOUT,
            FORMS,
            LISTS,
            NAVIGATION,
            COMPONENTS,
            PERFORMANCE,
            ACCESSIBILITY,
            CONTENT,
        ]
        .join("\n\n"),
        _ => section(INDEX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_topics_return_their_section() {
        assert!(guidance("layout").contains("panel-widths"));
        assert!(
            guidance("forms").contains("single column") || guidance("forms").contains("one column")
        );
        assert!(guidance("lists").contains("stretched-link"));
        assert!(guidance("navigation").contains("role=tablist"));
        assert!(
            guidance("components").contains("DRY") || guidance("components").contains("reusable")
        );
        assert!(guidance("performance").contains("virtualise"));
        assert!(guidance("accessibility").contains("accessible name"));
        assert!(guidance("content").contains("active voice"));
        assert!(
            guidance("copy").contains("empty state")
                || guidance("copy").contains("empty and error")
        );
    }

    #[test]
    fn all_includes_every_topic_and_the_index() {
        let all = guidance("all");
        for needle in [
            "Layout",
            "Forms",
            "Lists",
            "Navigation",
            "Components",
            "Performance",
            "Accessibility",
            "Content",
        ] {
            assert!(all.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn unknown_topic_falls_back_to_the_index() {
        assert!(guidance("nonsense").contains("Topics:"));
        assert!(guidance("").contains("Topics:"));
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(guidance("a11y"), guidance("accessibility"));
        assert_eq!(guidance("nav"), guidance("navigation"));
    }

    #[test]
    fn every_topic_keeps_its_rule_tags_and_a_calibrated_bar() {
        // The two things only uxlint supplies — the RULE that catches a miss, and a Testable bar —
        // must survive compression on every topic (the caller can infer the prose; not these).
        for topic in [
            "layout",
            "forms",
            "lists",
            "navigation",
            "components",
            "performance",
            "accessibility",
            "content",
        ] {
            let g = guidance(topic);
            assert!(g.contains("[rule:"), "{topic} lost its rule tags");
            assert!(g.contains("Testable:"), "{topic} lost its testable bar");
        }
    }
}
