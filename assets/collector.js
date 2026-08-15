// uxlint collector — baked into the CLI binary (include_str!), evaluated in the target page by the
// client. This file is the complete, auditable source of what an audit captures and uploads.
(() => {
// Runs in the browser (via page.evaluate). Must be fully self-contained — no outer refs.
// Returns a serializable snapshot (JSON) of the rendered page for the rules to analyze.
//
// ── WHAT THIS CAPTURES AND SENDS ──────────────────────────────────────────────────────────────
// Everything here is derived from the RENDERED page in your browser and returned to the CLI, which
// puts it in the per-page object it POSTs to the server (see audit.rs `build_audit_request`). It is
// all GEOMETRY, VISIBLE TEXT, and STYLE — never your source code, filesystem, or cookies. The
// notable data-bearing fields:
//   • docTitle / prose / sections / asides / codeText — visible page text (redacted, length-capped).
//   • elements[] — per-element role/label/rect/colours/text (each text field redacted + capped).
//   • tokens — the COLOUR custom properties your site declares on its root element, name + value
//     (`--brand-600: rgb(208, 30, 26)`). Colour-valued only: no spacing/font/content tokens.
//   • palette / css / framework / widgetLib — computed styles and the stack we detected.
//   • links, nav, breadcrumbs, headings, form-field labels — structure for the IA/nav lints.
//   • metaDescription / ogTags / iconLink — page <meta>, for SEO/preview lints.
//   • iframes[] — each embedded frame's box + visibility + the src's HOST (never the full URL: an
//     embed src can carry tokens/session ids in its query string, and the host alone answers
//     "first- or third-party?").
// All human-readable text runs through `redactSecrets` (the shared assets/redact.js patterns) before
// it leaves this function. Redaction is BEST-EFFORT, not a guarantee — see assets/redact.js.

function collectSnapshot() {
	const vw = window.innerWidth;
	const vh = window.innerHeight;

	// Canvas normalizes any CSS colour (oklab/oklch/hsl/named/hex — Tailwind v4 uses oklab for
	// /opacity) back to rgb(a) so we can read it uniformly.
	const cctx = (() => {
		try {
			return document.createElement('canvas').getContext('2d');
		} catch (_) {
			return null;
		}
	})();
	function oklabToRgb(L, A, B) {
		const l = (L + 0.3963377774 * A + 0.2158037573 * B) ** 3;
		const m = (L - 0.1055613458 * A - 0.0638541728 * B) ** 3;
		const s = (L - 0.0894841775 * A - 1.291485548 * B) ** 3;
		const lin = [
			4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
			-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
			-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s
		];
		const g = (c) => {
			c = c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055;
			return Math.round(Math.min(1, Math.max(0, c)) * 255);
		};
		return { r: g(lin[0]), g: g(lin[1]), b: g(lin[2]) };
	}
	function parseColor(str) {
		if (!str) return null;
		// oklab/oklch (Tailwind v4 uses these for /opacity). Canvas won't normalize them, so
		// convert to sRGB ourselves so contrast stays accurate.
		const ok = str.match(/^okl(ab|ch)\(([^)]*)\)/);
		if (ok) {
			const [head, alphaPart] = ok[2].split('/');
			const c = head.trim().split(/\s+/).map((x) => (x.endsWith('%') ? parseFloat(x) / 100 : parseFloat(x)));
			let A, B;
			if (ok[1] === 'ch') {
				const h = ((c[2] || 0) * Math.PI) / 180;
				A = (c[1] || 0) * Math.cos(h);
				B = (c[1] || 0) * Math.sin(h);
			} else {
				A = c[1] || 0;
				B = c[2] || 0;
			}
			let a = 1;
			if (alphaPart !== undefined) {
				const t = alphaPart.trim();
				a = t.endsWith('%') ? parseFloat(t) / 100 : parseFloat(t);
			}
			return { ...oklabToRgb(c[0] || 0, A, B), a: Number.isNaN(a) ? 1 : a };
		}
		if (!str.startsWith('rgb') && !str.startsWith('#') && cctx) {
			try {
				cctx.fillStyle = '#000';
				cctx.fillStyle = str;
				str = cctx.fillStyle;
			} catch (_) {
				/* keep original */
			}
		}
		if (str.startsWith('#')) {
			let h = str.slice(1);
			if (h.length === 3) h = h.split('').map((c) => c + c).join('');
			const n = parseInt(h, 16);
			return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255, a: 1 };
		}
		const m = str.match(/rgba?\(([^)]+)\)/);
		if (!m) return null;
		const p = m[1].split(/[\s,/]+/).filter(Boolean).map((x) => parseFloat(x));
		return { r: p[0], g: p[1], b: p[2], a: p[3] === undefined ? 1 : p[3] };
	}

	// A custom property's value AS A COLOUR, or null when it isn't one — the type filter for
	// `tokens` below. Canvas KEEPS ITS PREVIOUS fillStyle when handed something that isn't a
	// colour, so `--spacing: 4px` would read back as whatever we primed it with (i.e. every
	// non-colour token would land in the map as black). Prime with two different sentinels and
	// only trust a value that reads back identically from both.
	function colorToken(v) {
		v = (v || '').trim();
		if (!v || v.length > 64 || /[;{}]/.test(v)) return null;
		let c = null;
		if (/^okl(ab|ch)\(/i.test(v)) c = parseColor(v); // canvas won't normalize these
		else if (cctx) {
			try {
				cctx.fillStyle = '#000'; cctx.fillStyle = v; const dark = cctx.fillStyle;
				cctx.fillStyle = '#fff'; cctx.fillStyle = v; const light = cctx.fillStyle;
				if (dark === light) c = parseColor(dark);
			} catch (_) { return null; }
		} else if (/^(#|rgba?\(|hsla?\()/i.test(v)) c = parseColor(v);
		if (!c || !Number.isFinite(c.r) || !Number.isFinite(c.g) || !Number.isFinite(c.b)) return null;
		const rgb = [c.r, c.g, c.b].map((x) => Math.max(0, Math.min(255, Math.round(x))));
		// Emit rgb()/rgba(), never the source text: the server's colour parser reads hex and rgb
		// only, so a raw `oklch(...)` — what Tailwind v4 emits — would arrive unreadable and the
		// declared-brand path would stay dead for a different reason than the one we're fixing.
		const a = Math.round((Number.isFinite(c.a) ? c.a : 1) * 100) / 100;
		return a >= 1 ? `rgb(${rgb.join(', ')})` : `rgba(${rgb.join(', ')}, ${a})`;
	}

	// Design tokens: the COLOUR custom properties this site declares on its root element, resolved
	// for the theme that is actually rendering. This used to read a FIXED list of uxlint's OWN token
	// names (`--color-brand`, `--color-surface`, …), so it was `{}` on every site with a different
	// vocabulary — which is every site but ours — and `accent_hue`'s declared-brand path never ran.
	// We capture WHAT THE PAGE DECLARES and let the rules decide which name means "brand": that
	// decision is then a `cargo test` away from being tuned, where a list in here is a CLI release
	// away, every time. Colour-valued only — the non-colour half of a token set (spacing, easing,
	// font stacks) has no consumer today and would be ~4x the bytes; widening it is one line here
	// when a lint needs it.
	const TOKEN_MAX = 128;
	const tokens = (() => {
		const out = {};
		try {
			const root = document.documentElement;
			const rootCs = getComputedStyle(root);
			const names = new Set();
			// Computed style enumerates custom properties in current Chromium, and on its own that IS
			// the whole vocabulary: it reports what APPLIES to the root right now, so a token declared
			// on `html.dark` / `[data-theme="x"]` is already here, carrying the value the rendering
			// theme resolved to. Verified both ways against real captures: deleting the fallback below
			// changes nothing on this engine, and disabling THIS reproduces the same map through it.
			try { for (const p of rootCs) if (p.startsWith('--')) names.add(p); } catch (_) { /* ignore */ }
			try { for (const p of root.style) if (p.startsWith('--')) names.add(p); } catch (_) { /* ignore */ }
			if (!names.size) {
				// Only for an engine that DOESN'T enumerate them — we drive whatever Chrome the
				// machine already has, not a pinned build, and computed style exposed no custom
				// properties before Chrome 118. Names come from any rule THE ROOT ITSELF matches;
				// `matches` answers that exactly, where a selector regex mis-reads `:where(:root)` and
				// friends. Values still come from computed style, so a component-scoped token
				// resolves to '' and drops out regardless.
				let seen = 0;
				const walk = (rules, depth) => {
					for (const r of rules) {
						if (seen > 4000 || names.size > 400) return;
						if (r.cssRules && r.cssRules.length && depth < 6) walk(r.cssRules, depth + 1);
						if (!r.style || !r.selectorText) continue;
						seen++;
						const own = [];
						for (const p of r.style) if (p.startsWith('--')) own.push(p);
						if (!own.length) continue;
						try { if (!root.matches(r.selectorText)) continue; } catch (_) { continue; }
						for (const p of own) names.add(p);
					}
				};
				for (const sheet of document.styleSheets) {
					try { walk(sheet.cssRules, 0); } catch (_) { /* cross-origin sheet */ }
				}
			}
			let kept = 0;
			for (const n of names) {
				if (kept >= TOKEN_MAX) break;
				const c = colorToken(rootCs.getPropertyValue(n));
				if (c) { out[n.slice(0, 48)] = c; kept++; }
			}
		} catch (_) { /* a site's token vocabulary must never cost us the whole capture */ }
		return out;
	})();

	// HSL-ish hue + saturation from an {r,g,b} (0-255). Used to decide whether a fill/stroke is a
	// meaningful CATEGORY colour (a saturated, non-neutral hue) vs. structural ink (grey/near-white).
	function hueSat(c) {
		const r = c.r / 255, g = c.g / 255, b = c.b / 255;
		const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
		const l = (mx + mn) / 2;
		const sat = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
		let h = 0;
		if (d !== 0) {
			if (mx === r) h = ((g - b) / d) % 6;
			else if (mx === g) h = (b - r) / d + 2;
			else h = (r - g) / d + 4;
			h *= 60;
			if (h < 0) h += 360;
		}
		return { h, sat, l };
	}
	// Colour-encoding signal for a chart-sized <svg>: how many DISTINCT category colours its marks
	// use, and how many marks it has. A data viz that colour-codes ≥3 categories (each colour reused
	// across ≥2 marks) needs a legend; an illustration or single-series chart won't trip this. The
	// category colour of a mark is its saturated fill, or — when the fill is neutral (a bordered node)
	// — its saturated stroke, so severity-by-outline charts like our site-map are covered too.
	function vizSignal(el, w, h) {
		if (w < 180 || h < 100) return null;
		const shapes = el.querySelectorAll('rect,circle,ellipse,path,polygon');
		if (shapes.length < 4) return null;
		const buckets = new Map(); // 30°-hue bucket -> mark count
		let marks = 0;
		for (const sh of shapes) {
			if (marks > 600) break;
			const r = sh.getBoundingClientRect();
			if (r.width < 2 || r.height < 2) continue; // hairline/point, not a category mark
			marks++;
			const scs = getComputedStyle(sh);
			let cat = null;
			const fc = parseColor(scs.fill);
			if (fc && fc.a >= 0.2) {
				const hs = hueSat(fc);
				if (hs.sat >= 0.25 && hs.l > 0.12 && hs.l < 0.95) cat = hs.h;
			}
			if (cat === null) {
				const sc = parseColor(scs.stroke);
				if (sc && sc.a >= 0.2) {
					const hs = hueSat(sc);
					if (hs.sat >= 0.25 && hs.l > 0.12 && hs.l < 0.95) cat = hs.h;
				}
			}
			if (cat === null) continue;
			const b = Math.round(cat / 30) % 12;
			buckets.set(b, (buckets.get(b) || 0) + 1);
		}
		let cats = 0;
		for (const cnt of buckets.values()) if (cnt >= 2) cats++;
		return { vizMarks: marks, vizCats: cats };
	}

	// The page's own background (not an app-specific assumption): body/html computed bg,
	// else the white default canvas.
	const pageBg = (() => {
		for (const n of [document.body, document.documentElement]) {
			const c = parseColor(getComputedStyle(n).backgroundColor);
			if (c && c.a >= 0.5) return c;
		}
		return { r: 255, g: 255, b: 255, a: 1 };
	})();
	function effectiveBg(el) {
		let node = el;
		while (node && node.nodeType === 1) {
			const cs2 = getComputedStyle(node);
			const c = parseColor(cs2.backgroundColor);
			if (c && c.a >= 0.5) return c;
			// A background image/gradient makes the true backdrop unknowable — contrast
			// judgements against a guessed colour are worse than none.
			if (cs2.backgroundImage && cs2.backgroundImage !== 'none') return null;
			node = node.parentElement;
		}
		return pageBg;
	}

	function shortSel(el) {
		let s = el.tagName.toLowerCase();
		if (el.id) return s + '#' + el.id;
		const cls = (el.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean);
		if (cls.length) s += '.' + cls.slice(0, 2).join('.');
		const p = el.parentElement;
		if (p) {
			const idx = Array.from(p.children).indexOf(el) + 1;
			s += `:nth-child(${idx})`;
		}
		return s;
	}

	// Secret/PII redaction. The canonical patterns live in ONE place — assets/redact.js — and are
	// spliced in here at build time (see redact.rs `collector_js`), identically to every other
	// capture channel, so they cannot drift. `redactSecrets` is this channel's alias for the shared
	// `uxlintRedact`. See assets/redact.js for the best-effort disclaimer and pattern list.
	/*__UXLINT_REDACT__*/
	const redactSecrets = uxlintRedact;

	// Data-INDEPENDENT structural signature of an element: tag + role + its (sorted) class set + a
	// repetition-collapsed child-tag shape + which structural ARIA hooks it carries. Excludes text,
	// id, position, coordinates and data — so two renderings of the SAME component (a nav link on
	// every page, one card in a 50-row list, an empty-state block) share a signature while genuinely
	// different components don't. The audit keys element coverage on (rule, esig) to cover each
	// distinct element in a given state exactly ONCE, however many pages/times it appears.
	function esig(el) {
		return sigOf(el, (el.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean).sort().join('.'));
	}

	// The half of a signature that isn't the class set: tag, role, child shape, ARIA hooks. Shared by
	// `esig` and `fsig` so the two signatures can only ever differ in how they read the CLASS set.
	function sigOf(el, cls) {
		const tag = el.tagName.toLowerCase();
		const role = (el.getAttribute('role') || '').toLowerCase();
		let shape = '';
		let prev = '';
		for (const c of el.children) {
			const t = c.tagName.toLowerCase();
			if (t !== prev) { shape += t + ','; prev = t; } // collapse runs: 2 rows ≡ 50 rows
		}
		// PRESENCE of structural ARIA hooks (not their values, which are state/data).
		const aria = ['aria-label', 'aria-haspopup', 'aria-expanded', 'aria-controls', 'aria-modal']
			.map((a) => (el.hasAttribute(a) ? a[5] : '')).join('');
		const raw = tag + '|' + role + '|' + cls + '|' + shape + '|' + aria;
		let h = 0x811c9dc5;
		for (let i = 0; i < raw.length; i++) { h ^= raw.charCodeAt(i); h = Math.imul(h, 0x01000193); }
		return (h >>> 0).toString(36);
	}

	// ── Component FAMILY signature (`fsig`) — a COARSER companion to `esig`, never a replacement ──
	// `esig` is the exact RENDERING; `fsig` is the component the rendering came from. They answer two
	// different questions and both are needed:
	//   • esig → COVERAGE dedupe. A warning chip and a success chip genuinely differ in colour, so a
	//     contrast finding on one is NOT a finding on the other; coverage must keep them apart.
	//   • fsig → ATTRIBUTION. Those same chips are one <Chip> rendered with a different prop, so the
	//     fix is ONE edit. Root-cause grouping has to see all of them, or "fix the component, not the
	//     instances" reports the same defect three times and understates its blast radius by 3×.
	// Do NOT "simplify" these into one signature: whichever grain won, the other question would get
	// the wrong answer. Measured on a CSS-in-JS corpus site, the split is real — one MUI <Chip>
	// rendered 39 times carried 3 esigs (one per colour prop) and one nav item rendered 55 times
	// carried 2 (the active one wears an extra class).
	// fsig drops the class tokens that vary while the COMPONENT does not — generated/hashed names,
	// state classes, and variant modifiers of a block that also declares its base class — and keeps
	// everything else, including tag/role/shape/ARIA. Every rule below is deliberately reluctant:
	// failing to merge two renderings of one component only costs a duplicate finding, whereas
	// merging two genuinely different components files their findings under one wrong root cause.

	// Class tokens that name a STATE rather than a component — the active nav item, the open menu.
	// A closed list of conventional names, because an unrecognised token is kept (safe) while a
	// wrongly dropped one merges components (not safe).
	const STATE_CLASS = /^(?:is|has)[-_]|^(?:active|current|selected|checked|open|opened|closed|expanded|collapsed|disabled|enabled|hidden|shown|show|visible|focus|focused|focus-visible|hover|hovered|pressed|dragging|loading|busy|sticky|stuck|first|last|even|odd)$/i;
	// What's left of a generated token once its hash is stripped: a library's prefix, which names no
	// component (`css-1qz9irk` → `css`).
	const GENERIC_STUB = /^(?:css|jss|emotion|em|sc|style|styles|module|modules|makeStyles|useStyles)$/i;

	// Does a class-name run read as a generated HASH rather than a name? Judged structurally — vowel
	// density, syllable shape, digit placement, case noise — never against a library list, so an
	// unknown CSS-in-JS runtime is covered too. Tuned to answer NO on anything word-shaped: `hStack`,
	// `navBar`, `sizeSmall`, `colorSuccess`, `elevation0`, `bp4` and `flex` all survive it.
	function hashish(t) {
		const n = t.length;
		if (n < 4 || n > 12 || !/^[A-Za-z0-9]+$/.test(t)) return false;
		const big = (re) => Math.max(0, ...(t.match(re) || []).map((s) => s.length));
		const vowels = (t.match(/[aeiou]/gi) || []).length;
		// A name has syllables: a letter run long enough to pronounce, with no consonant pile-up.
		if (big(/[A-Za-z]+/g) > 3 && big(/[b-df-hj-np-tv-z]+/gi) < 4) return false;
		// emotion / CSS-Modules (`1qz9irk`, `lz0uxg`, `x1y2`) and lowercase runs like `tbnvsp`: a digit
		// INSIDE the run, or no vowel at all, on too few vowels for the length. A TRAILING number is a
		// scale step rather than a hash, so `elevation0`, `h3`, `bp4` and `col6` keep theirs.
		if ((vowels === 0 || /\d/.test(t.slice(0, -1))) && vowels * 3 <= n) return true;
		// styled-components (`hXlPTf`, `kQwWXy`, `iJKvXn`): short, case-noisy, vowel-starved.
		const CASE_RUNS = /[A-Z]+|[^A-Z]+/g;
		return n <= 8 && (t.match(CASE_RUNS) || []).length >= 3 && big(CASE_RUNS) <= 3 && vowels * 4 <= n;
	}

	// One class token reduced to the part that identifies a COMPONENT, or '' to drop it entirely.
	function familyToken(t) {
		if (STATE_CLASS.test(t)) return '';
		// styled-components emits a PAIR: a componentId (`sc-gzVnrw`), stable for the life of the
		// component and identical across all of its variants, plus a per-style-rule class that changes
		// with the props (`hXlPTf`). Svelte's `svelte-1x2abc` is the same idea, one per component FILE.
		// Such an id is precisely the identity we're after, so it is kept however hashy it looks — and
		// it is what stops a de-hashed element collapsing to no classes at all.
		if (/^(?:sc|svelte)-[A-Za-z0-9]+$/.test(t)) return t;
		const segs = t.split(/[-_]+/).filter(Boolean);
		const kept = segs.filter((s) => !hashish(s));
		if (kept.length === segs.length) return t; // nothing generated in it
		const rest = kept.join('-'); // `Button_root__x1y2` → `Button-root`
		return rest.length < 3 || GENERIC_STUB.test(rest) ? '' : rest;
	}

	function fsig(el) {
		const raw = (el.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean);
		const seen = [];
		for (const t of raw) {
			const f = familyToken(t);
			if (f && seen.indexOf(f) < 0) seen.push(f);
		}
		// A BLOCK that declares its base class (`MuiChip-root`, `btn`) alongside modifiers of the same
		// block (`MuiChip-colorWarning`, `btn-primary`) is one component wearing a prop: keep the base,
		// drop the modifiers. Only when the base is actually present — without it there is no evidence
		// the token is a modifier at all, and `card-header` must not collapse into `card`.
		const base = (t) => { const b = t.split('-')[0]; const r = t.slice(b.length + 1); return !r || r === 'root' || r === 'base' ? b : ''; };
		const based = new Set(seen.map(base).filter(Boolean));
		const cls = seen.filter((t) => base(t) || !based.has(t.split('-')[0]));
		// Nothing survived — an element whose only classes were state or hash. It must NOT fall into
		// the pool of class-LESS elements of its shape: with no stable token left there is no evidence
		// of a family at all, and filing 1000 bare <span>s under one root cause is the mis-attribution
		// this signature exists to prevent. Keep the exact class set (so fsig === esig, and the field
		// isn't even emitted) — no grouping is the honest answer when nothing identifies the component.
		return cls.length || !raw.length ? sigOf(el, cls.sort().join('.')) : esig(el);
	}

	// Framework fingerprint — synthetic-event frameworks change what "interactive" looks like.
	// JS cost: how much script ships, and how big the DOM it builds is. The numbers that
	// matter for a client-rendered app once JS is ON (not whether it needs JS).
	const js = (() => {
		try {
			let bytes = 0, count = 0, dev = false;
			for (const r of performance.getEntriesByType('resource')) {
				// Dev servers (Vite/webpack) serve unbundled modules — the byte/file count is
				// NOT the shipped bundle, so bundle-size findings would be misleading.
				if (/[/@](vite|@fs|@id)|node_modules\/\.vite|\.vite\/deps|__vite|webpack-dev|hot-update/.test(r.name)) dev = true;
				if (r.initiatorType === 'script' || /\.m?js(\?|$)/.test(r.name)) {
					bytes += r.encodedBodySize || r.transferSize || 0;
					count++;
				}
			}
			return { bytes, count, dev, domNodes: document.getElementsByTagName('*').length };
		} catch (_) { return { bytes: 0, count: 0, domNodes: 0 }; }
	})();

	const framework = (() => {
		try {
			if (document.querySelector('[ng-version]')) return 'angular';
			if (window.__NEXT_DATA__) return 'react-next';
			for (const el of document.querySelectorAll('#root, #app, [data-reactroot], body > div')) {
				for (const k in el) if (k.startsWith('__reactFiber') || k.startsWith('__reactContainer')) return 'react';
			}
			if (window.__VUE__ || document.querySelector('[data-v-app], [data-server-rendered]')) return 'vue';
			if (window.__svelte || document.querySelector('[class*="svelte-"]')) return 'svelte';
			if (window.__remixContext) return 'react-remix';
		} catch (_) { /* cross-origin guards etc. */ }
		return 'unknown';
	})();

	// Widget-set fingerprint — known class conventions, reported for context only.
	const widgetLib = (() => {
		try {
			const q = (sel) => !!document.querySelector(sel);
			if (q('[class*="Mui"]')) return 'mui';
			if (q('[class^="ant-"],[class*=" ant-"]')) return 'antd';
			if (q('[class*="chakra-"]')) return 'chakra';
			if (q('[class*="mantine-"]')) return 'mantine';
			if (q('[data-radix-scroll-area-viewport],[data-radix-popper-content-wrapper]')) return 'radix';
			if (q('[class*="v-application"],[class*="v-btn"]')) return 'vuetify';
			if (q('[class*="p-component"]')) return 'prime';
			if (q('[class*="bp4-"],[class*="bp5-"]')) return 'blueprint';
			if (q('[class*="ui-widget"]')) return 'jquery-ui';
		} catch (_) { /* ignore */ }
		return null;
	})();

	// Source-CSS hygiene: walk same-origin stylesheets for dead selectors, !important
	// wars and deep-specificity chains. State-ish selectors (.open, [aria-…]) are treated
	// as dynamic, not dead.
	const css = (() => {
		const st = { sheets: 0, cross: 0, rules: 0, important: 0, deep: [], unused: [], checked: 0 };
		const DYNAMICISH = /\.(open|active|show|shown|visible|expanded|collapsed|hidden|selected|current|dragging|loading|is-|has-)|\[data-|\[aria-|\[open/;
		try {
			const walk = (rules) => {
				for (const r of rules) {
					if (st.rules >= 4000) return;
					// CSS nesting gave CSSStyleRule a cssRules too — process the rule
					// itself first, then recurse (media/supports/nested alike).
					if (r.cssRules && r.cssRules.length) walk(r.cssRules);
					if (!r.selectorText) continue;
					st.rules++;
					st.important += ((r.cssText || '').match(/!important/g) || []).length;
					for (const sel of r.selectorText.split(',')) {
						const s0 = sel.trim();
						const units = s0.split(/[\s>+~]+/).filter(Boolean);
						if (units.length >= 5 && st.deep.length < 5) st.deep.push(s0.slice(0, 80));
						const s1 = s0.replace(/::?[\w-]+(\([^)]*\))?/g, '').trim();
						if (!s1 || DYNAMICISH.test(s0)) continue;
						try {
							st.checked++;
							if (!document.querySelector(s1) && st.unused.length < 300) st.unused.push(s0.slice(0, 80));
						} catch (_) { st.checked--; }
					}
				}
			};
			for (const sheet of document.styleSheets) {
				st.sheets++;
				try { walk(sheet.cssRules); } catch (_) { st.cross++; }
			}
		} catch (_) { /* never sink an audit for stats */ }
		return st;
	})();

	// Mobile & perceived-performance page signals (Wave 4).
	let mobile = { viewportMeta: '', zoomBlocked: false, fontFaceNoDisplay: 0, autoplayNoControl: 0 };
	try {
		const vp = document.querySelector('meta[name="viewport"]');
		mobile.viewportMeta = vp ? (vp.getAttribute('content') || '') : '';
		const v = mobile.viewportMeta.toLowerCase().replace(/\s+/g, '');
		// Pinch-zoom disabled — a WCAG 1.4.4 failure and a usability wall on mobile.
		mobile.zoomBlocked = /user-scalable=(no|0)/.test(v) || /maximum-scale=(1|1\.0|0)(,|;|$)/.test(v + ';');
		// @font-face without font-display causes a flash of invisible text (FOIT).
		for (const sheet of document.styleSheets) {
			try {
				for (const r of sheet.cssRules) {
					const txt = r.cssText || '';
					if ((r.constructor && r.constructor.name === 'CSSFontFaceRule') || txt.startsWith('@font-face')) {
						if (!/font-display/i.test(txt)) mobile.fontFaceNoDisplay++;
					}
				}
			} catch (_) { /* cross-origin sheet */ }
		}
		// Autoplaying media with no pause control — motion the user can't stop.
		for (const m of document.querySelectorAll('video[autoplay], audio[autoplay]')) {
			if (!m.hasAttribute('controls')) mobile.autoplayNoControl++;
		}
	} catch (_) { /* ignore */ }

	// Prose sample for slop/clarity lints: body copy only, capped.
	let prose = '';
	try {
		for (const el of document.querySelectorAll('p, li, blockquote, dd, figcaption')) {
			if (prose.length > 6000) break;
			const t = redactSecrets((el.innerText || '').trim());
			if (t.length > 40) prose += t + '\n';
		}
	} catch (_) { /* ignore */ }

	// Date markers (©, last updated) for the staleness lint — usually in short footers the
	// prose sample skips for being under its length floor. Own-text only, code excluded.
	// `footer` is in the list because `<footer>© 2019 Acme</footer>` — the notice as the
	// footer's OWN text, with no wrapper element — is the commonest way anyone writes one, and
	// leaving it out made stale-copyright-year silently blind to the canonical case.
	let dateMarkers = [];
	try {
		for (const el of document.querySelectorAll('p, li, small, span, time, dd, address, div, footer')) {
			if (dateMarkers.length >= 6) break;
			if (el.closest('code,pre,kbd,samp,blockquote,q,[data-example],[data-uxlint-example]')) continue;
			let t = '';
			for (const c of el.childNodes) if (c.nodeType === 3) t += c.textContent;
			t = t.replace(/\s+/g, ' ').trim();
			if (t.length > 3 && t.length < 80 && /(©|\(c\)|copyright|last updated|last modified|updated on)/i.test(t)) {
				dateMarkers.push(t.slice(0, 64));
			}
		}
	} catch (_) { /* ignore */ }

	// Code comments in marketing snippets ARE copy (a "# one static binary" comment speaks
	// to the visitor) — collected separately so code stays exempt from grammar/slop rules.
	let asides = '';
	try {
		for (const el of document.querySelectorAll('pre')) {
			for (const line of (el.innerText || '').split('\n')) {
				const t = line.trim();
				if (/^(#|\/\/)\s*[A-Za-z]/.test(t) && t.length > 12 && asides.length < 1500) asides += t + '\n';
			}
		}
	} catch (_) { /* ignore */ }

	// FULL code-block text (every <pre> line, not just comments), redacted and capped. Per-element
	// `text` is sliced to 400 chars, which buries a coined SUBCOMMAND shown late in a multi-line
	// command block (e.g. a `tool zenith` example after six other commands); the unexplained-concept
	// judge reads this so those feature names in commands stay visible. Template text (commands/config),
	// so no grammar/copy lint reads it.
	let codeText = '';
	try {
		for (const el of document.querySelectorAll('pre, code')) {
			if (el.closest('pre') && el.tagName === 'CODE') continue; // avoid double-counting <pre><code>
			const t = redactSecrets((el.innerText || '').replace(/\s*\n\s*/g, '\n').trim());
			if (t && codeText.length < 2500) codeText += t + '\n';
		}
	} catch (_) { /* ignore */ }

	// Intra-page structure: the heading outline (knowledge clusters) and every anchorable
	// id (fragment-link targets) — sub-nodes of the page in the site graph.
	// Sections are CONTENT nodes: each heading carries the information its paragraphs
	// impart (word count + gist), not just a title.
	const sections = [];
	const headingEls = []; // DOM node per section, parallel to `sections`, for structural attribution
	try {
		let cur = null;
		for (const el of document.querySelectorAll('h1,h2,h3,h4,p,li,blockquote,dl,table,pre,figure,img,svg,canvas,iframe,video,progress,meter,[role="progressbar"],[role="meter"]')) {
			// Only what's actually RENDERED is part of the page's outline. A closed <dialog> (and any
			// display:none subtree) still holds its markup, and innerText falls back to textContent for
			// unrendered nodes — so without this a modal's heading joins every page's section list and
			// poisons the section lints (order, scope, emptiness).
			const rects = el.getClientRects();
			if (!rects.length) continue;
			const tag = el.tagName.toUpperCase(); // SVG/HTML tagName case differs
			if (/^H[1-4]$/.test(tag)) {
				if (sections.length >= 60) break;
				const t = redactSecrets((el.innerText || '').trim());
				if (!t) continue;
				cur = { level: +el.tagName[1], text: t.slice(0, 80), id: el.id || '', words: 0, gist: '', hasMedia: false };
				sections.push(cur);
				headingEls.push(el);
			} else if (cur && (tag === 'PROGRESS' || tag === 'METER' || el.matches('[role="progressbar"],[role="meter"]'))) {
				// A gauge/progress meter (storage used, quota, completion) IS the section's content —
				// a "Storage" heading over a usage bar keeps its promise even with no prose words.
				cur.hasMedia = true;
			} else if (cur && /^(DL|TABLE|PRE|FIGURE|IMG|SVG|CANVAS|IFRAME|VIDEO)$/.test(tag)) {
				// A section's content can be a list, table, code block, figure, image or diagram — not
				// just prose. Mark it so a word-light section built from these isn't called empty.
				// Size-gate the inline-capable media (an icon isn't section content).
				if (/^(DL|TABLE|PRE|FIGURE|IFRAME|VIDEO)$/.test(tag)) cur.hasMedia = true;
				else { const r = rects[0]; if (r.width >= 80 && r.height >= 40) cur.hasMedia = true; }
			} else if (cur) {
				const t = redactSecrets((el.innerText || '').trim());
				if (!t) continue;
				cur.words += t.split(/\s+/).length;
				if (cur.gist.length < 400) cur.gist += t.slice(0, 400 - cur.gist.length) + ' ';
			}
		}
		for (const sec of sections) sec.gist = sec.gist.trim();
	} catch (_) { /* ignore */ }

	// Structural scope signal (no keywords): a content <select> that DUPLICATES a shell/nav switcher
	// — shares ≥2 option labels with a <select> living outside <main> — is a re-implemented context
	// picker. The section holding it makes you choose which INSTANCE the setting applies to, so the
	// setting is scoped to that instance; sitting on a global route is the misplacement. Mark it.
	try {
		const main = document.querySelector('main, [role="main"]') || document.body;
		// Key options by their VALUE (usually the instance id) — the same org is often LABELLED
		// differently in two switchers ("Personal (personal)" vs "Personal workspace"), but its
		// underlying value/id is stable, so ids are the reliable match.
		const optSet = (s) =>
			new Set(Array.from(s.options || []).map((o) => (o.value || o.textContent || '').trim().toLowerCase()).filter(Boolean));
		// Candidate context switchers: selects in the shell (outside main) offering a real choice.
		const shellOpts = Array.from(document.querySelectorAll('select'))
			.filter((s) => !main.contains(s))
			.map(optSet)
			.filter((o) => o.size >= 2);
		if (shellOpts.length && headingEls.length) {
			for (const s of main.querySelectorAll('select')) {
				const opts = optSet(s);
				if (opts.size < 2) continue;
				const dup = shellOpts.some((so) => {
					let n = 0;
					for (const o of opts) if (so.has(o)) n++;
					return n >= 2;
				});
				if (!dup) continue;
				// Attribute to its section: the nearest heading that PRECEDES this select in the document.
				let best = -1;
				for (let i = 0; i < headingEls.length; i++) {
					if (headingEls[i].compareDocumentPosition(s) & Node.DOCUMENT_POSITION_FOLLOWING) best = i;
				}
				if (best >= 0) sections[best].embedsCtx = true;
			}
		}
	} catch (_) { /* ignore */ }
	// Junk-drawer / limbo buckets: a heading with a catch-all label (Unattached, Uncategorised,
	// Orphaned, Ungrouped, Other, Misc…) sitting over a real collection of items — the app leaking
	// its internal data model to the user. Conservative: the label must START with the term AND a
	// list/grid of >=3 items must follow, so a stray "Other" heading over prose never fires.
	const junkBuckets = [];
	try {
		const LIMBO = /^\s*(unattached|uncategori[sz]ed|un-?categori[sz]ed|orphan(ed|s)?|ungrouped|unsorted|miscellaneous|misc|no\s+(category|group|folder|site)|other)\b/i;
		for (const h of document.querySelectorAll('h1,h2,h3,h4,h5,h6,[role="heading"]')) {
			const t = (h.textContent || '').replace(/\s+/g, ' ').trim();
			if (!t || !LIMBO.test(t)) continue;
			const r = h.getBoundingClientRect();
			if (r.height < 4 || h.offsetParent === null) continue;
			// The collection this heading introduces: a following list/grid, else one in its box.
			const sib = h.nextElementSibling;
			let container = sib && /^(UL|OL)$/.test(sib.tagName) ? sib : null;
			if (!container && sib) container = sib.querySelector('ul,ol,[class*="grid" i]');
			if (!container && h.parentElement) container = h.parentElement.querySelector('ul,ol,[class*="grid" i]');
			const count = container ? container.children.length : 0;
			if (count >= 3) junkBuckets.push({ label: t.slice(0, 40), count });
			if (junkBuckets.length >= 5) break;
		}
	} catch (_) { /* ignore */ }
	let anchorIds = [];
	let idEls = []; // the same elements anchorIds is derived from — reused by scrollOffsets below,
	// so "is this element a fragment target?" is answered off ONE list, not two that can drift.
	try {
		idEls = Array.from(document.querySelectorAll('[id]')).filter((e) => e.id).slice(0, 300);
		anchorIds = idEls.map((e) => e.id);
	} catch (_) { /* ignore */ }

	// Fragment-jump offsets. A same-page `href="#panels"` aligns the target with the TOP of the
	// scrollport — i.e. UNDERNEATH a sticky/fixed bar, hiding the very heading the reader asked for —
	// unless the offset is declared somewhere: `scroll-padding-top` on the scroller (the usual right
	// fix, on `html`, and it covers every target at once) or `scroll-margin-top` on the target itself.
	// Only the DECLARATIONS live here; the bar's geometry is already in the snapshot, so the rule can
	// pair them without us deciding anything about bars.
	const scrollOffsets = (() => {
		const out = { padTop: 0 };
		try {
			// Which ids does this page actually jump to? `a.host`/`a.pathname`/`a.hash` are the RESOLVED
			// URL, so a relative `#panels` and an absolute `/docs#panels` written on /docs both compare
			// as same-document, while a link to another page's anchor correctly doesn't count.
			const targeted = new Set();
			for (const a of document.querySelectorAll('a[href]')) {
				if (a.host !== location.host || a.pathname !== location.pathname) continue;
				let frag = (a.hash || '').slice(1);
				if (!frag) continue;
				try { frag = decodeURIComponent(frag); } catch (_) { /* malformed escape — match raw */ }
				targeted.add(frag);
				if (targeted.size >= 300) break;
			}
			const targets = idEls.filter((e) => targeted.has(e.id)).slice(0, 60);
			// The scrollport that actually moves. Normally the document; in an app shell whose body
			// doesn't scroll it's an inner overflow container, and that's where the padding has to sit
			// for the jump to clear the bar — reading `html` there would report a fix that does nothing.
			let scroller = document.scrollingElement || document.documentElement;
			if (targets.length && scroller.scrollHeight <= scroller.clientHeight + 1) {
				for (let p = targets[0].parentElement; p && p !== document.body; p = p.parentElement) {
					const oy = getComputedStyle(p).overflowY;
					if ((oy === 'auto' || oy === 'scroll') && p.scrollHeight > p.clientHeight + 1) { scroller = p; break; }
				}
			}
			// `scroll-padding-top` is NOT one of the properties CSSOM resolves to used pixels, so a
			// percentage arrives as "10%" (of the scrollport's height) and an unset one as "auto" —
			// which behaves as 0 for this purpose. Resolve both here so the server only ever sees px.
			const raw = (getComputedStyle(scroller).scrollPaddingTop || 'auto').trim();
			// `px`, not `n` — the element loop below declares a function-scope `let n`, and a name that
			// resolved to it from in here would be a temporal-dead-zone ReferenceError at capture time.
			const px = parseFloat(raw) || 0; // "auto" → NaN → 0
			out.padTop = Math.round(raw.endsWith('%') ? (px * (scroller.clientHeight || vh)) / 100 : px);
			// Per-target `scroll-margin-top` — the other place the offset can be declared, and the one
			// that has to be repeated on every target. Percentages aren't valid on scroll-margin, so
			// the computed value is already px.
			if (targets.length) {
				const t = {};
				for (const el of targets) t[el.id] = Math.round(parseFloat(getComputedStyle(el).scrollMarginTop) || 0);
				out.targets = t;
			}
		} catch (_) { /* unsupported prop — report nothing declared */ }
		return out;
	})();

	const INTERACTIVE = new Set(['A', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'SUMMARY']);
	const MEDIA = new Set(['IMG', 'VIDEO', 'SVG', 'CANVAS']);
	const els = [];
	const nodeToIdx = new Map(); // DOM node -> index in `els`, for parent/sibling checks
	// Floating layer: fixed/sticky elements and their subtrees form a stacking context OVER the page
	// flow. Tag them so (a) grouping/counting lints treat them as a distinct context (an overlay's
	// controls don't compete with the page's own), and (b) a finding on one annotates against the
	// VIEWPORT — where it actually sits over the content it covers — not the stitched full-page image.
	// Propagated in document order (querySelectorAll returns parents before children), so a child
	// inherits its ancestor's tag without a per-element parent walk.
	const floatingSet = new WeakSet();
	const nodes = document.body.querySelectorAll('*');
	let n = 0;
	for (const el of nodes) {
		if (n >= 4000) break;
		const cs = getComputedStyle(el);
		// `cs.display`/`cs.visibility` are the element's OWN styles — they stay "block"/"visible" even
		// when an ANCESTOR is display:none, so a heading inside a responsive `lg:hidden` bar looked
		// present on the wrong breakpoint (two <h1>s counted, one never rendered). getClientRects() is
		// empty for anything not rendered (own or inherited display:none); fixed/sticky still have rects.
		if (cs.display === 'none' || cs.visibility === 'hidden' || el.getClientRects().length === 0)
			continue;
		const inFloating =
			cs.position === 'fixed' ||
			cs.position === 'sticky' ||
			(el.parentElement !== null && floatingSet.has(el.parentElement));
		if (inFloating) floatingSet.add(el);
		const rect = el.getBoundingClientRect();

		let text = '';
		for (const c of el.childNodes) if (c.nodeType === 3) text += c.textContent;
		text = redactSecrets(text.replace(/\s+/g, ' ').trim());

		// Actual rendered line count of a LEAF element's text: a Range over its contents reports one
		// client rect per line-box. This is the honest "does the label wrap?" signal — unlike
		// box-height ÷ line-height, it isn't fooled by a flex-centred or fixed-height control (a
		// 24px tap-target button around a 12px emoji) being taller than its single line of text.
		let textLines = 0;
		if (text && el.childElementCount === 0) {
			try {
				const rng = document.createRange();
				rng.selectNodeContents(el);
				const tops = new Set();
				for (const r of rng.getClientRects()) if (r.width > 0.5 && r.height > 0.5) tops.add(Math.round(r.top));
				textLines = tops.size;
			} catch (_) {}
		}

		// Is this text inside a visually distinct CARD (bordered / rounded / filled container)?
		// Text in a card is inset by the card's own padding, so its left edge legitimately differs
		// from body text outside — don't let that read as a misalignment.
		let inCard = false;
		if (text && /^(P|H1|H2|H3|H4|LI|BLOCKQUOTE|DD)$/.test(el.tagName)) {
			for (let pc = el.parentElement, dc = 0; pc && dc < 8 && pc !== document.body && pc.tagName !== 'MAIN'; pc = pc.parentElement, dc++) {
				const pcs = getComputedStyle(pc);
				const pbw = pcs.borderTopStyle !== 'none' ? parseFloat(pcs.borderTopWidth) || 0 : 0;
				const prad = parseFloat(pcs.borderTopLeftRadius) || 0;
				const pbg = parseColor(pcs.backgroundColor);
				if (pbw >= 1 || prad >= 6 || (pbg && pbg.a > 0.1)) { inCard = true; break; }
			}
		}

		// Weird clipping: an element cut off by a non-scrollable overflow-hidden ancestor.
		// Excludes legitimate cases — collapsible/animating panels clip on purpose and only
		// transiently, and object-fit images are designed crops.
		let clipFrac = 0;
		try {
			if (rect.width > 6 && rect.height > 6 && el.offsetParent !== null) {
				const elPos = cs.position; // the element's OWN position governs which overflow clips it
				for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
					const pcs = getComputedStyle(p);
					const ov = pcs.overflow + pcs.overflowX + pcs.overflowY;
					if (/(auto|scroll)/.test(ov)) break; // scrollable = reachable, not clipped
					if (!/(hidden|clip)/.test(ov)) continue;
					// An absolutely/fixed-positioned element is clipped ONLY by its CONTAINING BLOCK —
					// a positioned ancestor, or one with a transform/filter/perspective/paint-containment
					// (which establish one). A plain static overflow ancestor does NOT clip it, so it
					// isn't cut off however far its box falls outside. (Works below the fold, unlike the
					// elementFromPoint probe.)
					if (elPos === 'absolute' || elPos === 'fixed') {
						const cb =
							pcs.transform !== 'none' ||
							pcs.filter !== 'none' ||
							pcs.perspective !== 'none' ||
							pcs.willChange === 'transform' ||
							/(paint|layout|strict|content)/.test(pcs.contain || '');
						const clips = elPos === 'fixed' ? cb : cb || pcs.position !== 'static';
						if (!clips) continue; // not this element's containing block → doesn't clip it
					}
					// Collapsible / mid-animation panel? Then any clip is intentional + transient.
					const collapsible =
						p.hasAttribute('aria-expanded') ||
						p.closest('[aria-expanded],details,[data-state],[data-collapsed]') !== null ||
						parseFloat(pcs.transitionDuration) > 0 ||
						pcs.maxHeight !== 'none';
					if (collapsible) break;
					const pr = p.getBoundingClientRect();
					if (pr.width < 4 || pr.height < 4) break; // collapsed container
					const visW = Math.max(0, Math.min(rect.right, pr.right) - Math.max(rect.left, pr.left));
					const visH = Math.max(0, Math.min(rect.bottom, pr.bottom) - Math.max(rect.top, pr.top));
					const area = rect.width * rect.height;
					if (area > 0) clipFrac = 1 - (visW * visH) / area;
					// Geometry alone lies: an element's box can fall outside an overflow-hidden ancestor
					// yet be fully visible (odd legacy layouts, transforms, one-axis overflow). Only
					// TRUST a clip we can positively confirm — probe a point in the clipped region and
					// require the element to NOT be painted there. If it's painted (false alarm) OR the
					// point is off-screen (below the fold — can't probe), treat it as not clipped.
					if (clipFrac > 0.05 && area > 0) {
						let sx = rect.left + rect.width / 2;
						let sy = rect.top + rect.height / 2;
						if (rect.bottom - pr.bottom > 1) sy = rect.bottom - Math.min(rect.height, rect.bottom - pr.bottom) / 2;
						else if (pr.top - rect.top > 1) sy = rect.top + Math.min(rect.height, pr.top - rect.top) / 2;
						if (rect.right - pr.right > 1) sx = rect.right - Math.min(rect.width, rect.right - pr.right) / 2;
						else if (pr.left - rect.left > 1) sx = rect.left + Math.min(rect.width, pr.left - rect.left) / 2;
						let confirmed = false;
						if (sx >= 1 && sy >= 1 && sx <= innerWidth - 1 && sy <= innerHeight - 1) {
							const at = document.elementFromPoint(sx, sy);
							confirmed = !(at && (at === el || el.contains(at))); // NOT painted there ⇒ really clipped
						}
						if (!confirmed) clipFrac = 0;
					}
					break; // nearest clipping ancestor decides
				}
			}
		} catch (_) { /* ignore */ }

		// Text truncated by line-clamp or ellipsis, with real content hidden and no way to
		// read it (no title tooltip, not a link to detail). "…" that leads nowhere.
		let truncated = false;
		try {
			// Substantial hidden content only — a multi-line clamp hiding half again as much,
			// or a single line ellipsis hiding a good chunk. Headings are labels, not content.
			const isHeading = /^H[1-6]$/.test(el.tagName);
			const clampY = /hidden|clip/.test(cs.overflowY) && (cs.webkitLineClamp !== 'none' || cs.display === '-webkit-box') && el.scrollHeight > el.clientHeight * 1.5;
			const ellipsisX = cs.textOverflow === 'ellipsis' && el.scrollWidth > el.clientWidth * 1.5;
			if (!isHeading && (clampY || ellipsisX) && (el.innerText || '').trim().length > 40) truncated = true;
		} catch (_) { /* ignore */ }

		const role = el.getAttribute('role');
		// React/Vue attach listeners synthetically — el.onclick is null on their clickables.
		// A pointer-ROOT (cursor:pointer here, not inherited from the parent) is the reliable
		// cross-framework signal for "this thing is clickable".
		const parentCursor = el.parentElement ? getComputedStyle(el.parentElement).cursor : '';
		const pointerRoot = cs.cursor === 'pointer' && parentCursor !== 'pointer';
		const interactive =
			INTERACTIVE.has(el.tagName) ||
			role === 'button' ||
			role === 'link' ||
			(typeof el.onclick === 'function') ||
			pointerRoot;
		const isMedia = MEDIA.has(el.tagName);
		if (!text && !interactive && !isMedia && rect.width * rect.height < 1) continue;

		const fontSize = parseFloat(cs.fontSize) || 0;
		let lineHeight = parseFloat(cs.lineHeight);
		if (!lineHeight || cs.lineHeight === 'normal') lineHeight = fontSize * 1.2;

		// Inside a horizontally-scrollable ancestor? (then overflow / off-screen is expected)
		let inScrollX = false;
		for (let p = el.parentElement; p && p.nodeType === 1; p = p.parentElement) {
			const pcs = getComputedStyle(p);
			if ((pcs.overflowX === 'auto' || pcs.overflowX === 'scroll') && p.scrollWidth > p.clientWidth + 1) {
				inScrollX = true;
				break;
			}
		}

		// Occlusion: is an interactive element's own centre actually hittable? Use the FIRST
		// client rect, not the bounding box — a wrapped inline link (2 lines) has a bounding
		// centre in the gap between lines, which hits other text and false-flags occlusion.
		let occluded = false;
		const rects = el.getClientRects();
		const orect = rects.length ? rects[0] : rect;
		const cx = orect.left + orect.width / 2;
		const cy = orect.top + orect.height / 2;
		// Only real controls (a single box). A wrapped inline link in prose has multiple rects
		// and is never meaningfully "covered" — checking it just false-flags occlusion. An inline
		// link that happens to fit on ONE line is the same non-control: its centre can resolve to a
		// neighbouring text run, so exclude inline anchors too (buttons / block / inline-block links
		// and other controls still get checked).
		const inlineProseLink = el.tagName === 'A' && cs.display === 'inline';
		// A "stretched link" / overlay: an EMPTY positioned control sized to its offsetParent — the
		// `absolute inset-0` whole-row click target. It's DESIGNED to sit behind the row's content and
		// its z-layered actions (Delete, a label editor), so its centre resolving to one of those is the
		// pattern working, not a bug. Skip occlusion for it. Kept tight (empty + covers the parent) so a
		// real hidden control — which carries a label/icon and isn't parent-sized — is still caught.
		let overlayStretch = false;
		if ((cs.position === 'absolute' || cs.position === 'fixed') && !(el.textContent || '').trim()) {
			const op = el.offsetParent;
			if (op) {
				const pr = op.getBoundingClientRect();
				const near = (a, b) => Math.abs(a - b) <= 2;
				overlayStretch = near(orect.left, pr.left) && near(orect.top, pr.top) && near(orect.width, pr.width) && near(orect.height, pr.height);
			}
		}
		if (interactive && !inlineProseLink && !overlayStretch && rects.length === 1 && orect.width > 2 && orect.height > 2 && cx >= 0 && cy >= 0 && cx <= vw && cy <= vh) {
			// A covering element must actually be THERE: elementFromPoint returns null for a point that
			// isn't hit-testable — chiefly a control straddling the fold, whose centre lands on the
			// viewport's bottom edge (cy === innerHeight). Null is INCONCLUSIVE, not "covered", so
			// require a real `top`; treating null as occlusion false-flagged every below-fold control.
			const top = document.elementFromPoint(cx, cy);
			occluded = !!top && !(top === el || el.contains(top) || top.contains(el));
			// …but a control "covered" by an open MODAL isn't a stacking BUG — it's intentionally
			// behind a dialog scrim, and EVERY background control would otherwise false-flag (a
			// first-run tutorial / onboarding overlay lights up the whole page → dozens of bogus
			// occlusions). Only a LOCAL cover — a mispositioned neighbour, a sticky bar overlapping —
			// is the real defect. So discount occlusion when the covering element is (or sits inside)
			// a role=dialog / aria-modal, or any positioned ancestor that BLANKETS the viewport (a
			// full-screen scrim). The full-viewport requirement keeps genuine local covers flagged.
			if (occluded && top.closest('[role="dialog"],[role="alertdialog"],[aria-modal="true"]')) {
				occluded = false;
			}
			// A cookie-CONSENT banner is expected, must-interact chrome — dismissed on the first click,
			// the same category as a dialog scrim — so a control it temporarily covers is not a stacking
			// bug. Every site pins one to an edge, so flagging what it covers would be a universal false
			// positive. Discount when the occluder sits inside a pinned element whose own text is a
			// consent notice.
			if (occluded) {
				for (let a = top; a && a !== document.body; a = a.parentElement) {
					const ap = getComputedStyle(a).position;
					if (ap !== 'fixed' && ap !== 'sticky') continue;
					const t = (a.textContent || '').toLowerCase();
					if (t.includes('cookie') && /consent|accept|essential|analytics|we use|preferences|privacy/.test(t)) {
						occluded = false;
						break;
					}
				}
			}
			if (occluded) {
				for (let a = top; a && a !== document.body; a = a.parentElement) {
					const ap = getComputedStyle(a);
					if (ap.position !== 'fixed' && ap.position !== 'absolute') continue;
					const ar = a.getBoundingClientRect();
					if (ar.left <= 2 && ar.top <= 2 && ar.width >= vw - 2 && ar.height >= vh - 2) {
						occluded = false;
						break;
					}
				}
			}
			// A sticky/fixed bar covers whatever is beneath it AT THE CURRENT SCROLL POSITION, and the
			// interaction passes leave the page scrolled (the hover walk wanders; focus scrolls things
			// into view). So a control that is perfectly clear at rest can be hit-tested at the moment a
			// sticky header sits over it — reported from the field as four toolbar controls "covered",
			// with the report's own screenshot showing them plainly visible. That cover is a fact about
			// where we were looking, not about the layout. At scrollY === 0 the same sticky bar over the
			// same control IS a real defect, and still fires.
			if (occluded && window.scrollY > 0) {
				for (let a = top; a && a !== document.body; a = a.parentElement) {
					const ap = getComputedStyle(a).position;
					if (ap === 'sticky' || ap === 'fixed') {
						occluded = false;
						break;
					}
				}
			}
		}

		// Reverse of occlusion: does this element FLOAT ON TOP of and cover LARGE text? A positioned
		// control over a heading/number (a pin over a grade, a badge over a title) is a layout
		// collision. Sample the box corners+centre; if big visible text sits directly beneath it in
		// the paint order (and isn't its own ancestor/descendant), flag it.
		let coversText = false;
		// Label of the LARGE text this element sits on, so the finding can name what's buried
		// ("hides the 'Dashboard' heading"), not just the cover. Position-agnostic: a nav toggle
		// over the header trips this whether pinned top-left (Material) or top-right (the Android
		// convention), because we sample every corner + the centre.
		let coveredText = '';
		// A full-viewport overlay (a modal scrim, a dialog backdrop, a readability wash) covers
		// everything by design — not the "positioned control colliding with a heading" this catches;
		// it false-flagged background text behind an open dialog. Only a LOCAL cover counts.
		const isScrim = orect.left <= 2 && orect.top <= 2 && orect.width >= vw - 2 && orect.height >= vh - 2;
		if (!isScrim && (cs.position === 'absolute' || cs.position === 'fixed') && orect.width > 6 && orect.height > 6) {
			const pts = [[orect.left + 2, orect.top + 2], [orect.right - 2, orect.top + 2], [orect.left + 2, orect.bottom - 2], [orect.right - 2, orect.bottom - 2], [cx, cy]];
			for (const [px, py] of pts) {
				if (px < 0 || py < 0 || px > vw || py > vh) continue;
				let stack; try { stack = document.elementsFromPoint(px, py); } catch (_) { continue; }
				const mi = stack.indexOf(el);
				if (mi < 0) continue;
				for (let i = mi + 1; i < stack.length && i <= mi + 4; i++) {
					const u = stack[i];
					if (!u || el.contains(u) || u.contains(el)) continue;
					const ut = (u.textContent || '').replace(/\s+/g, ' ').trim();
						if (ut && parseFloat(getComputedStyle(u).fontSize) >= 20) { coversText = true; coveredText = ut.slice(0, 40); break; }
				}
				if (coversText) break;
			}
		}

		// Padding waste: a header/nav BAR whose height is mostly empty padding around a small logo or
		// label (a 77px drawer header over a 28px logo). Measure the vertical extent of the bar's own
		// content (its element children) against its height. Scoped to bar-shaped CHROME — position
		// sticky/fixed, or <header>/<nav> — so heroes, cards and content sections (legitimately padded,
		// and tall rather than bar-shaped) never trip it.
		let padWasteV;
		if (
			(cs.position === 'fixed' || cs.position === 'sticky' || el.tagName === 'HEADER' || el.tagName === 'NAV') &&
			orect.width > orect.height && orect.height >= 40 && orect.height <= 160
		) {
			let ctop = Infinity, cbot = -Infinity;
			for (const c of el.children) {
				const crs = getComputedStyle(c);
				if (crs.display === 'none' || crs.visibility === 'hidden') continue;
				const cr = c.getBoundingClientRect();
				if (cr.width < 1 || cr.height < 1) continue;
				ctop = Math.min(ctop, cr.top);
				cbot = Math.max(cbot, cr.bottom);
			}
			if (cbot > ctop) {
				const waste = 1 - (cbot - ctop) / orect.height;
				if (waste > 0) padWasteV = Math.round(waste * 100) / 100;
			}
		}

		// Accessible name + labelling (for tooltip / grouping checks).
		const ariaLabel = el.getAttribute('aria-label');
		const titleAttr = el.getAttribute('title');
		const altAttr = el.getAttribute('alt');
		const labelledby = el.getAttribute('aria-labelledby');
		const namedByAttr = !!((ariaLabel || titleAttr || altAttr || labelledby || '').trim());
		// Disabled AT LOAD, and whether a reason is attached. `disabled-without-reason` (Wave-3 D)
		// keys on both: :disabled matches native form controls (incl. those inside a disabled
		// <fieldset>), aria-disabled covers custom/role controls. `hasDescribedby` is true only when
		// aria-describedby actually RESOLVES to non-empty text — a bare id pointing at nothing is not
		// an explanation. Presence of the reason is all we record here (a boolean); its TEXT is never
		// captured, so nothing describing the control can leak into a model prompt.
		let disabled = false;
		let hasDescribedby = false;
		try {
			disabled =
				(typeof el.matches === 'function' && el.matches(':disabled')) ||
				el.getAttribute('aria-disabled') === 'true';
			const db = (el.getAttribute('aria-describedby') || '').trim();
			if (db) {
				hasDescribedby = db.split(/\s+/).some((id) => {
					const t = id && document.getElementById(id);
					return !!(t && (t.innerText || t.textContent || '').trim());
				});
			}
		} catch (_) { /* ignore */ }
		const isControl = ['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName);
		const inputType = el.tagName === 'INPUT' ? (el.getAttribute('type') || 'text') : null;
		let inFieldset = false;
		for (let p = el.parentElement; p; p = p.parentElement)
			if (p.tagName === 'FIELDSET') { inFieldset = true; break; }
		let labelled = !!(ariaLabel || labelledby);
		if (isControl && !labelled) {
			try {
				if (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) labelled = true;
				else if (el.closest && el.closest('label')) labelled = true;
			} catch (_) { /* ignore */ }
		}
		// Form-field signals (Wave 2). Only text-entry inputs — checkboxes/radios/buttons
		// don't have the same labelling/autocomplete/keyboard concerns.
		let field;
		if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
			const t = (inputType || 'text').toLowerCase();
			if (!['hidden', 'checkbox', 'radio', 'button', 'submit', 'reset', 'image', 'range', 'color', 'file'].includes(t)) {
				const ph = (el.getAttribute('placeholder') || '').trim();
				// Does the placeholder (the instructions shown INSIDE the box) actually FIT, or is it cut
				// off? A too-narrow text box clips its placeholder ("Enter your emai…"), so the guidance
				// can't be read. Measure the placeholder in the field's OWN font against its inner content
				// width (padding excluded), the way the browser paints it. Single-line <input> only — a
				// <textarea> wraps its placeholder, so it isn't clipped horizontally. `+4` avoids a
				// hairline-rounding false positive; only a clearly-over-width placeholder counts.
				let placeholderClipped = false;
				if (ph && el.tagName === 'INPUT') {
					try {
						const cs = getComputedStyle(el);
						const inner = el.clientWidth - parseFloat(cs.paddingLeft || '0') - parseFloat(cs.paddingRight || '0');
						const ctx2d = (window.__uxMeasureCtx || (window.__uxMeasureCtx = document.createElement('canvas').getContext('2d')));
						if (inner > 0 && ctx2d) {
							ctx2d.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
							placeholderClipped = ctx2d.measureText(ph).width > inner + 4;
						}
					} catch (_) { /* ignore */ }
				}
				// "purpose" from name/id/autocomplete/type — used for autocomplete + type checks.
				const hint = `${el.getAttribute('name') || ''} ${el.id || ''} ${el.getAttribute('autocomplete') || ''} ${ph}`.toLowerCase();
				let purpose = null;
				if (/\b(e-?mail)\b/.test(hint) || t === 'email') purpose = 'email';
				else if (/\b(phone|tel|mobile)\b/.test(hint) || t === 'tel') purpose = 'tel';
				// Person-name only — an EXPLICIT first/last/full/your-name phrase. A bare "name"
				// is ambiguous ("organization name", "site name") and autocomplete=name would be
				// wrong there, so it's deliberately not matched.
				else if (/\b(first|last|full|given|family)[\s_-]*name\b|\byour name\b/.test(hint)) purpose = 'name';
				else if (/\b(street|address|city|zip|postal|postcode|country)\b/.test(hint)) purpose = 'address';
				else if (/\bpassword\b/.test(hint) || t === 'password') purpose = 'password';
				// Numeric-keypad fields: an unambiguous count/code (a promo "code" is alphanumeric,
				// so it's deliberately excluded — only verification/PIN/CVV/quantity/age).
				else if (/\b(quantity|qty|count|age|pin|cvv|cvc|otp|verification)\b/.test(hint) || t === 'number') purpose = 'number';
				else if (/\b(url|website|homepage)\b/.test(hint) || t === 'url') purpose = 'url';
				else if (/\bsearch\b/.test(hint) || t === 'search') purpose = 'search';
				// Field's human name for form-length judging: associated <label>, aria-label,
				// placeholder, or the name attr — whatever a person would call it.
				let flabel = (el.getAttribute('aria-label') || '').trim();
				if (!flabel && el.id) { try { const lb = document.querySelector(`label[for="${CSS.escape(el.id)}"]`); if (lb) flabel = (lb.innerText || '').trim(); } catch (_) {} }
				if (!flabel && el.closest) { const lb = el.closest('label'); if (lb) flabel = (lb.innerText || '').trim(); }
				if (!flabel) flabel = ph || (el.getAttribute('name') || '');
				// Where the visible <label> sits relative to the field — the biggest form-layout lever.
				// TOP-aligned labels form one clean column and complete fastest (Penzo eye-tracking;
				// Baymard); BESIDE-the-field (left) labels are slower and read as a grid. A WRAPPING
				// label (box encloses the input) is ambiguous, so left unset — as are placeholder-/
				// aria-only fields (no visible <label> to place).
				let labelPos = null;
				try {
					let lb = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`) : null;
					if (!lb && el.closest) lb = el.closest('label');
					if (lb) {
						const lr = lb.getBoundingClientRect();
						const wraps = lr.left <= rect.left + 1 && lr.right >= rect.right - 1 && lr.top <= rect.top + 1 && lr.bottom >= rect.bottom - 1;
						// A VISUALLY-HIDDEN label (sr-only: 1px, clipped) has no on-screen placement — its
						// tiny rect must not be read as "above" or "beside". Require a real visible box.
						if (lr.width >= 8 && lr.height >= 8 && !wraps) {
							if (lr.bottom <= rect.top + 4) labelPos = 'top';
							else if (lr.right <= rect.left + 4 && lr.top < rect.bottom && lr.bottom > rect.top) labelPos = 'left';
						}
					}
				} catch (_) { /* ignore */ }
				field = {
					type: t,
					label: redactSecrets(flabel.replace(/\s+/g, ' ').trim()).slice(0, 40),
					hasPlaceholder: !!ph,
					labelledByPlaceholderOnly: !!ph && !labelled && !namedByAttr,
					autocomplete: (el.getAttribute('autocomplete') || '').trim().toLowerCase() || null,
					inputMode: (el.getAttribute('inputmode') || '').trim().toLowerCase() || null,
					required: el.hasAttribute('required') || el.getAttribute('aria-required') === 'true',
					purpose,
					labelPos,
					// maxlength when set — lets the width lint know a field expects only a few chars
					maxLength: el.maxLength > 0 ? el.maxLength : null,
					// A number input carries no maxlength, but its `max`/`min` bound how many DIGITS it
					// holds — the width lint infers a short capacity from them (a 4-digit max wants a
					// small box). Only for type=number, only when numeric.
					numMax: t === 'number' && el.max !== '' && isFinite(+el.max) ? +el.max : null,
					numMin: t === 'number' && el.min !== '' && isFinite(+el.min) ? +el.min : null,
					// The placeholder/instructions text is cut off by a too-narrow box (measured above).
					placeholderClipped
				};
			}
		}
		const rawTxt = (el.textContent || '').trim();
		const hasSvg = !!(el.querySelector && el.querySelector('svg,img,use,canvas'));

		// Broken image: fully loaded but zero natural size means the src failed or is empty —
		// the browser paints a broken-image glyph where a picture should be.
		const imgBroken =
			el.tagName === 'IMG' && el.complete && (el.naturalWidth || 0) === 0 &&
			!!(el.getAttribute('src') || '').trim();
		// Junk alt text: present but meaningless (a filename, "image", "img_1234") — worse than
		// nothing because it's read aloud verbatim. alt-MISSING is a separate rule.
		let altJunk = false;
		let altText;
		if (el.tagName === 'IMG' && altAttr && altAttr.trim()) {
			const a = altAttr.trim();
			altJunk =
				/^(image|img|photo|picture|graphic|untitled)[0-9_ -]*$/i.test(a) ||
				/\.(png|jpe?g|gif|webp|svg|avif)$/i.test(a) ||
				/^[\w-]+\d{2,}$/.test(a);
			// Keep the alt for every captioned image (not just junk) — alt-mismatch (VLM)
			// compares it against the rendered pixels. Junk-alt keys on the altJunk flag.
			altText = redactSecrets(a).slice(0, 120);
		}
		// Placeholder content shipped live: unrendered template tokens, lorem ipsum, dev markers
		// — the most embarrassing class of visible bug. Scan the element's OWN text only, skip
		// code samples (a <code>undefined</code> is legit) and site chrome.
		let placeholders;
		{
			const contentTag = /^(P|H[1-6]|LI|TD|DT|DD|BUTTON|A|SPAN|FIGCAPTION)$/.test(el.tagName);
			const inCode = !!(el.closest && el.closest('code,pre,kbd,samp,blockquote,q,[data-example],[data-uxlint-example]'));
			const chrome = !!(el.closest && el.closest('nav,header,footer,[role="navigation"],[role="banner"],[role="contentinfo"]'));
			if (text && contentTag && !inCode && !chrome) {
				const CHECKS = [
					[/lorem ipsum/i, 'lorem ipsum'],
					[/\b(TODO|FIXME|XXX)\b:?/, 'TODO/FIXME'],
					[/\{\{\s*[\w.]+\s*\}\}/, 'unrendered {{…}}'],
					[/\$\{[\w.]+\}/, 'unrendered ${…}'],
					[/\bundefined\b/, 'undefined'], // case-sensitive: the JS literal, not prose
					[/\bNaN\b/, 'NaN'],
					[/\[object Object\]/, '[object Object]'],
				];
				const hits = [];
				for (const [re, label] of CHECKS) {
					if (re.test(text)) hits.push(label);
					if (hits.length >= 5) break;
				}
				if (hits.length) placeholders = hits;
			}
		}

		// CSS hygiene: static inline styles belong in a stylesheet. Dynamic values
		// (sizes, transforms, custom properties) are legitimate inline.
		const styleRaw = el.getAttribute('style') || '';
		let styleDecls = 0;
		if (styleRaw) {
			const DYNAMIC = /^(--|width$|height$|min-|max-|top$|left$|right$|bottom$|inset|transform|translate|opacity$|display$|visibility$|z-index$|position$|background-image$|clip)/;
			for (const d of styleRaw.split(';')) {
				const p = (d.split(':')[0] || '').trim().toLowerCase();
				if (p && !DYNAMIC.test(p)) styleDecls++;
			}
		}
		const styleSig = styleDecls >= 2 ? styleRaw.replace(/\s+/g, '').slice(0, 80) : null;
		const ziRaw = parseInt(cs.zIndex, 10);

		// Semantic widget-type inference for ROLE-LESS custom controls. No library
		// knowledge: (a) structural duck-typing (a switch LOOKS like a thumb in a pill
		// track), (b) the site's own naming (developers call the class what it is).
		const widgetGuess = (() => {
			if (role || isControl || ['A', 'BUTTON', 'SUMMARY', 'DIALOG', 'LABEL'].includes(el.tagName)) return null;
			// An element that WRAPS a native form control (a <label> around a checkbox, a styled
			// container around a <select>) already carries that control's role — it's not a role-less
			// custom widget, so don't duck-type one out of its wrapper's classes. (FP: a "Show archived"
			// <label class="flex items-center"> around an <input type=checkbox> read as a custom select.)
			try { if (el.querySelector && el.querySelector('input, select, textarea')) return null; } catch (_) { /* ignore */ }
			const name = (el.getAttribute('class') || '') + ' ' + (el.id || '');
			const hit = (re) => re.test(name);
			try {
				if (interactive) {
					// switch: pill-shaped track holding a round thumb child
					const pill = (parseFloat(cs.borderTopLeftRadius) || 0) >= rect.height / 2 - 1;
					let thumb = false;
					if (el.firstElementChild) {
						const t = el.firstElementChild.getBoundingClientRect();
						thumb = t.height > 6 && Math.abs(t.width - t.height) < 4 &&
							t.height <= rect.height && t.width < rect.width * 0.7;
					}
					if ((pill && thumb && rect.height >= 12 && rect.height <= 44 &&
						rect.width >= rect.height * 1.5 && rect.width <= rect.height * 3.5) ||
						hit(/\b(switch|toggle)\b/i)) return 'switch';
					if (hit(/\b(combobox|autocomplete|typeahead)\b/i)) return 'combobox';
					if ((/[▾▼⌄]$/.test(rawTxt.slice(0, 80)) && text) ||
						hit(/\b(select|dropdown|picker)\b/i)) return 'select';
					if (hit(/\b(slider|range)\b/i) && !isControl) return 'slider';
					if (hit(/\btabs?\b/i)) return 'tab';
					if (hit(/\bcheckbox\b/i)) return 'checkbox';
					if (hit(/\bradio\b/i)) return 'radio';
					if (hit(/\b(accordion|collapse|expander)\b/i)) return 'accordion';
					if (hit(/\bmenu-?item\b/i)) return 'menuitem';
				} else if (cs.position === 'fixed' || cs.position === 'absolute') {
					if (hit(/\b(modal|dialog|drawer)\b/i) && rect.width > 200) return 'dialog';
					if (hit(/\btooltip\b/i)) return 'tooltip';
				}
			} catch (_) { /* ignore */ }
			return null;
		})();
		// Icon-only means no text ANYWHERE in the subtree — a card wrapping an svg
		// sparkline plus text children is labelled by its content, not icon-only.
		const iconOnly =
			interactive &&
			((hasSvg && text.length === 0 && rawTxt.trim().length === 0) ||
				(rawTxt.length > 0 && rawTxt.length <= 2 && !/[a-z0-9]/i.test(rawTxt) && el.childElementCount <= 1));

		const ownBg = parseColor(cs.backgroundColor);
		const ariaHidden =
			el.getAttribute('aria-hidden') === 'true' || !!(el.closest && el.closest('[aria-hidden="true"]'));

		// Scan-pattern signals: main-content membership (excluding nav chrome that happens to
		// live inside <main>) and "primary action" styling.
		const inMain = !!(el.closest && el.closest('main') && !el.closest('nav'));
		const inNav = !!(el.closest && el.closest('nav'));
		// A breadcrumb trail is NOT a menu bar: its links have no menu-row position/colour affordance,
		// so a resting underline actually aids discoverability. Detect it (labelled nav, breadcrumb
		// class, or a nav whose descendant marks the current page) so nav-styling lints can skip it.
		const inBreadcrumb = !!(el.closest && el.closest(
			'nav[aria-label*="breadcrumb" i], [class*="breadcrumb" i], [aria-label*="breadcrumb" i]'
		)) || !!(el.closest && (() => { const n = el.closest('nav'); return n && n.querySelector('[aria-current="page"]'); })());
		// NOTE: there is deliberately no `isPrimary` here. It used to be `interactive &&
		// /\bbg-brand\b/` — a test for uxlint's OWN Tailwind class, so it was false on every element
		// of every other site, and four lints spent their lives reasoning about a constant. "Primary
		// action" is a comparison against the PAGE's accent hue, which is an aggregate this per-
		// element loop doesn't have; the server does (`accent_hue`), and every input it needs already
		// rides — `interactive`, `bgA`, `bgRgb` (emitted below whenever the fill is ≥50% opaque, the
		// same gate the derivation uses) and `palette`. So the verdict belongs there, with its
		// chroma/hue thresholds unit-testable, not here behind a CLI release.

		// Nearest already-collected ancestor.
		let parentIdx = -1;
		for (let p = el.parentElement; p; p = p.parentElement)
			if (nodeToIdx.has(p)) { parentIdx = nodeToIdx.get(p); break; }
		const idx = els.length;

		// Colour-encoding signal — computed only for <svg> roots (cheap; svgs are rare). Note: SVG
		// elements aren't in the HTML namespace, so tagName stays lowercase ("svg", not "SVG").
		const vz = el.tagName.toLowerCase() === 'svg' ? vizSignal(el, rect.width, rect.height) : null;

		// Component identity at two grains — the exact rendering, and the component family. This loop
		// has no try/catch of its own, so `fsig` — much the more intricate of the two — gets one here:
		// falling back to the exact rendering costs one un-grouped element, throwing costs the whole
		// page's capture.
		const es = esig(el);
		let fs = es;
		try { fs = fsig(el); } catch (_) { /* keep es — no family is better than no snapshot */ }

		els.push({
			idx,
			parentIdx,
			sel: shortSel(el),
			esig: es,
			// Component FAMILY (see `fsig`): the same element grouped by which COMPONENT it came
			// from, so root-cause attribution can say "one fix, N instances". OMITTED when it equals
			// `esig` — the common case on hand-written CSS, where nothing in the class set varies per
			// rendering — so it costs no bytes on most sites. A missing `fsig` means "same as esig".
			fsig: fs === es ? undefined : fs,
			tag: el.tagName.toLowerCase(),
			role: role || null,
			position: cs.position,
			namedByAttr,
			hasTitle: !!(titleAttr && titleAttr.trim()),
			truncated,
			isControl,
			inputType,
			inFieldset,
			labelled,
			iconOnly,
			ariaHidden,
			radius: parseFloat(cs.borderTopLeftRadius) || 0,
			borderW: cs.borderTopStyle !== 'none' ? parseFloat(cs.borderTopWidth) || 0 : 0,
			borderBW: cs.borderBottomStyle !== 'none' ? parseFloat(cs.borderBottomWidth) || 0 : 0,
			bgA: ownBg ? ownBg.a : 0,
			bgRgb: ownBg && ownBg.a >= 0.5 ? { r: ownBg.r, g: ownBg.g, b: ownBg.b } : null,
			borderRgb:
				cs.borderTopStyle !== 'none' && parseFloat(cs.borderTopWidth) > 0
					? parseColor(cs.borderTopColor)
					: null,
			// box-shadow STRENGTH — the max alpha among the shadow's colours (0 = no shadow). A faint
			// shadow (low alpha) delineates a panel no better than none; `hasRing` (a boolean) can't
			// tell them apart, so a near-invisible card needs the actual alpha.
			shadowA: (() => {
				const s = cs.boxShadow;
				if (!s || s === 'none') return 0;
				let a = 0;
				const re = /rgba?\(([^)]+)\)/g;
				let m;
				while ((m = re.exec(s))) {
					const parts = m[1].split(/[,\s/]+/).filter(Boolean);
					const al = parts.length >= 4 ? parseFloat(parts[3]) : 1;
					if (!isNaN(al)) a = Math.max(a, al);
				}
				if (a === 0 && !/rgba?\(/.test(s)) a = 1; // named-colour shadow → opaque
				return Math.round(a * 100) / 100;
			})(),
			textAlign: cs.textAlign,
			x: Math.round(rect.left * 10) / 10,
			// Where TEXT actually begins (content-box left) — padding/border on a wrapper shifts the
			// box edge but not the text, so alignment is judged on this, not `x`.
			textX: Math.round((rect.left + (parseFloat(cs.borderLeftWidth) || 0) + (parseFloat(cs.paddingLeft) || 0)) * 10) / 10,
			inCard,
			y: Math.round(rect.top * 10) / 10,
			w: Math.round(rect.width * 10) / 10,
			h: Math.round(rect.height * 10) / 10,
			text: text.slice(0, 400),
			textLen: text.length,
			textLines,
			interactive,
			isMedia,
			color: parseColor(cs.color),
			bg: text ? effectiveBg(el) : null,
			fontSize,
			fontWeight: parseInt(cs.fontWeight) || 400,
			lineHeight,
			whiteSpace: cs.whiteSpace,
			underline: cs.textDecorationLine.includes('underline'),
			overflowX: cs.overflowX,
			overflowY: cs.overflowY,
			textOverflow: cs.textOverflow,
			lineClamp: parseInt(cs.webkitLineClamp) || 0, // >0 = intentional multi-line clamp
			padTop: parseFloat(cs.paddingTop) || 0,
			padLeft: parseFloat(cs.paddingLeft) || 0,
			scrollW: el.scrollWidth,
			clientW: el.clientWidth,
			scrollH: el.scrollHeight,
			clientH: el.clientHeight,
			naturalW: el.naturalWidth || 0,
			naturalH: el.naturalHeight || 0,
			// A click-to-enlarge thumbnail: an image inside a link/button that opens a larger view.
			// Its full-res source is used when opened, so it's not "overweight". (Images only.)
			imgClickable: el.tagName === 'IMG' && !!el.closest('a[href],button,[role="button"]'),
			// Text inside code/quote/sample blocks (or an element explicitly marked as example copy)
			// is quoted content, not live UI — pattern lints that scan visible text (stale years,
			// leaked secrets, placeholder strings, hard-coded locations) must ignore it, or a page
			// that merely *documents* a UX problem looks like it *has* one. See the copyright FP.
			inQuote: !!el.closest('code,pre,kbd,samp,blockquote,q,[data-example],[data-uxlint-example]'),
			objectFit: cs.objectFit,
			// Chart colour-encoding (svg only; omitted otherwise): distinct category colours + mark count.
			vizMarks: vz ? vz.vizMarks : undefined,
			vizCats: vz ? vz.vizCats : undefined,
			clipFrac: Math.round(clipFrac * 100) / 100,
			// Guard NaN (a detached / display:none node yields no numeric opacity): unguarded it
			// serializes as JSON `null`, which the server's f64 opacity field rejects (422s the whole
			// audit). Default to fully opaque, preserving a legit 0. Every other numeric field here
			// already has its own `|| 0` guard.
			opacity: Number.isFinite(parseFloat(cs.opacity)) ? parseFloat(cs.opacity) : 1,
			cursor: cs.cursor,
			childElems: el.childElementCount,
			inMain,
			inNav,
			inBreadcrumb,
			inFloating,
			coversText,
			coveredText: coveredText || undefined,
			padWasteV,
			pointerRoot,
			widgetGuess,
			href: el.tagName === 'A' ? redactSecrets(el.getAttribute('href') || '').slice(0, 120) : null,
			styleDecls,
			styleSig,
			zIndex: Number.isFinite(ziRaw) ? ziRaw : null,
			// Class signature for coverage-gap feedback: only for role-less pointer controls
			// we could NOT classify (sel may hold the id instead, which drops the classes).
			classSig: (pointerRoot && !role && !widgetGuess)
				? ((el.getAttribute('class') || '').trim().split(/\s+/).filter(Boolean).slice(0, 2).join('.') || null)
				: null,
			draggableAttr: el.getAttribute('draggable') === 'true',
			// Drag ROOT: the element that establishes the grab affordance, not children
			// that merely inherit its cursor (mirror of pointerRoot for clicks).
			dragRoot:
				el.getAttribute('draggable') === 'true' ||
				(['grab', 'grabbing', 'move'].includes(cs.cursor) && cs.cursor !== parentCursor),
			ariaKeyshortcuts: el.getAttribute('aria-keyshortcuts') || null,
			tabindex: el.getAttribute('tabindex'),
			ariaModal: el.getAttribute('aria-modal'),
			ariaHaspopup: el.getAttribute('aria-haspopup'),
			ariaExpanded: el.getAttribute('aria-expanded'),
			ariaChecked: el.getAttribute('aria-checked'),
			ariaCurrent: el.getAttribute('aria-current'),
			ariaPressed: el.getAttribute('aria-pressed'),
			ariaSelected: el.getAttribute('aria-selected'),
			hasRing: cs.boxShadow !== 'none',
			// Accessible-name computation walks DESCENDANTS: a wrapper link whose text
			// lives in child spans (a card) is NOT icon-only. Own text wins (truer to
			// the visible label); the subtree is the fallback, like AT computes it.
			label: interactive
				? redactSecrets((ariaLabel || titleAttr || text || rawTxt || '').replace(/\s+/g, ' ').trim()).slice(0, 60)
				: null,
			titleText: titleAttr ? redactSecrets(titleAttr.replace(/\s+/g, ' ').trim()).slice(0, 120) : null,
			inScrollX,
			occluded,

			// Wave-1 content-integrity signals (omitted when absent to keep the snapshot lean).
			imgBroken: imgBroken || undefined,
			altJunk: altJunk || undefined,
			altText,
			placeholders,
			field,
			// Load-time disabled state + whether a reason is attached (Wave-3 D). Omitted when false
			// to keep the snapshot lean; the Rust field defaults to false for old clients.
			disabled: disabled || undefined,
			hasDescribedby: hasDescribedby || undefined
		});
		nodeToIdx.set(el, idx);
		n++;
	}

	// ── rendered palette (for colour-scheme rules) ────────────────────────────
	// Every colour the user actually sees, weighted by how much of it they see. Approximate
	// (nested fills double-count a little) but stable enough to lint hue discipline and
	// accent share. kind: 'bg' | 'text' | 'border'.
	const palette = [];
	for (const e of els) {
		if (e.ariaHidden || e.y > vh * 3) continue;
		const visW = Math.min(Math.max(e.w, 0), vw);
		const visH = Math.max(e.h, 0);
		if (e.bgA >= 0.5 && e.bgRgb && visW * visH > 64)
			palette.push({ kind: 'bg', c: e.bgRgb, area: visW * visH, sel: e.sel, interactive: e.interactive });
		if (e.textLen > 0 && e.color)
			palette.push({ kind: 'text', c: e.color, area: e.textLen * e.fontSize * (e.fontSize * 0.55), sel: e.sel, interactive: e.interactive });
		if (e.borderW > 0 && e.borderRgb)
			palette.push({ kind: 'border', c: e.borderRgb, area: 2 * (visW + visH) * e.borderW, sel: e.sel, interactive: e.interactive });
	}

	// ── Searchability: can users search/filter to find things, or must they scroll? ──
	// A large uniform collection (cards, rows, list items) with no search or filter forces
	// users to eyeball every item. Detect both the affordance and the collection size.
	let searchable = false;
	try {
		const SEARCH_SEL =
			'input[type=search],[role=search],[role=searchbox],' +
			'input[aria-label*="search" i],input[placeholder*="search" i],input[name*="search" i],' +
			'input[aria-label*="filter" i],input[placeholder*="filter" i],input[name*="filter" i]';
		searchable = !!document.querySelector(SEARCH_SEL);
		if (!searchable) {
			// A select/combobox/button whose accessible name is about filtering/sorting/searching.
			for (const el of document.querySelectorAll('select,button,[role=combobox],[role=listbox],[role=button]')) {
				const name = (
					(el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '') + ' ' +
					(el.getAttribute('name') || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('class') || '')
				).toLowerCase();
				if (/\b(filter|sort|search)\b/.test(name)) { searchable = true; break; }
			}
		}
	} catch (_) { /* ignore */ }

	// Largest uniform collection: the biggest group of same-signature (tag + first class)
	// sibling items on the page. Site chrome (nav/footer) is excluded — it isn't content.
	let collectionMax = 0;
	let collectionKind = '';
	let collectionSel = ''; // CSS path to the collection's container — the finding's locator into the DOM
	let collectionRect = null; // bounding box of the biggest collection (top portion), for previews
	// Can you DRILL INTO the biggest collection? i.e. do its items lead to a detail view
	// (each item is/contains a link or button). A flat pile of entities that go nowhere is
	// an IA dead-end — feeds flat-app-structure.
	let collectionDrillable = false;
	try {
		let bestParent = null;
		for (const parent of document.querySelectorAll('*')) {
			// <head> is not a collection: a static/SPA build ships dozens of <link rel=modulepreload>
			// + <meta> there, and the SPA injects more chunk links at runtime — which counted as a
			// "30-45 items, add a search box" finding on EVERY page. None of it renders, so it isn't
			// something a user scans. Skip it outright (the per-child visibility gate below is the
			// general guard; this is the cheap, exact one).
			if (parent === document.head) continue;
			const kids = parent.children;
			if (kids.length < 12) continue;
			// Exclude site chrome AND pagination controls — a pager is not the collection.
			if (parent.closest('nav,footer,[role=navigation],[role=menu],[role=menubar],[role=tablist],[class*="paginat" i],[class*="pager" i],[aria-label*="pagination" i]')) continue;
			const counts = new Map();
			for (const k of kids) {
				const tag = k.tagName;
				if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEMPLATE' || tag === 'BR') continue;
				// Count only what actually renders. An item with no box — head metadata, a display:none
				// mega-menu, a hidden template row — is not something a user scrolls and scans, so it
				// must not inflate the collection the searchability lint gates on.
				if (!k.getClientRects().length) continue;
				const cls = (k.getAttribute('class') || '').trim().split(/\s+/)[0] || '';
				const sig = tag + (cls ? '.' + cls : '');
				const n = (counts.get(sig) || 0) + 1;
				counts.set(sig, n);
				if (n > collectionMax) { collectionMax = n; collectionKind = sig; bestParent = parent; }
			}
		}
		if (bestParent) {
			collectionSel = shortSel(bestParent); // path into the DOM so a finding names WHERE the pile is
			// Sample the collection's items: is a meaningful share of them a link (or contain one)?
			const items = Array.from(bestParent.children).filter(k => !['SCRIPT','STYLE','TEMPLATE','BR'].includes(k.tagName));
			let linked = 0;
			for (const k of items) {
				const isLink = k.tagName === 'A' && k.getAttribute('href') ||
					k.matches('[role="link"], button, [role="button"]') ||
					k.querySelector('a[href], button, [role="button"], [role="link"]');
				if (isLink) linked++;
			}
			collectionDrillable = items.length > 0 && linked / items.length >= 0.5;
			// Anchor previews at the TOP of the collection — where a search box / pager belongs and
			// the first rows are visible — not the full (possibly page-tall) list.
			const cr = bestParent.getBoundingClientRect();
			if (cr.width > 1 && cr.height > 1) collectionRect = [cr.x, cr.y, cr.width, Math.min(cr.height, 260)].map(Math.round);
		}
	} catch (_) { /* ignore */ }

	// The TALLEST drillable list, for height-based pagination. Pagination is about how far the list
	// makes you scroll, not the raw item count — a dozen tall rows can be a 2000px wall while a
	// hundred thin rows fit. So we find the tallest uniform, drillable, same-signature sibling group
	// (>= 6 items, chrome/pagers excluded) and record its full pixel height + item count. Uses a
	// lower item floor than collectionMax on purpose; the lint gates on HEIGHT.
	let listHeight = 0;
	let listItems = 0;
	// How much of each row is actually clickable: 1 = the whole row is a link, ~0.2 = only a small
	// inner link (e.g. just the date) navigates. Median across the tallest list's rows. Drives the
	// "make the whole row a click target" lint.
	let listRowLinkCoverage = 1;
	try {
		let bestList = null;
		for (const parent of document.querySelectorAll('ul,ol,tbody,div,section,main')) {
			const kids = Array.from(parent.children).filter((k) => !['SCRIPT', 'STYLE', 'TEMPLATE', 'BR'].includes(k.tagName));
			if (kids.length < 6) continue;
			if (parent.closest('nav,footer,[role=navigation],[role=menu],[role=menubar],[role=tablist],[class*="paginat" i],[class*="pager" i],[aria-label*="pagination" i]')) continue;
			const counts = new Map();
			for (const k of kids) {
				const cls = (k.getAttribute('class') || '').trim().split(/\s+/)[0] || '';
				const sig = k.tagName + (cls ? '.' + cls : '');
				counts.set(sig, (counts.get(sig) || 0) + 1);
			}
			const dominant = Math.max(0, ...counts.values());
			if (dominant < 6) continue; // needs a real uniform run, not a mixed container
			let linked = 0;
			for (const k of kids) {
				if ((k.tagName === 'A' && k.getAttribute('href')) || k.matches('[role="link"], button, [role="button"]') || k.querySelector('a[href], button, [role="button"], [role="link"]')) linked++;
			}
			if (linked / kids.length < 0.5) continue; // must be drillable
			const r = parent.getBoundingClientRect();
			if (r.height > listHeight) {
				listHeight = r.height;
				listItems = dominant;
				bestList = parent;
			}
		}
		listHeight = Math.round(listHeight);
		if (bestList) {
			const items = Array.from(bestList.children).filter((k) => !['SCRIPT', 'STYLE', 'TEMPLATE', 'BR'].includes(k.tagName));
			const covs = [];
			for (const it of items) {
				const ir = it.getBoundingClientRect();
				const area = ir.width * ir.height;
				if (area < 64) continue;
				// The whole row IS a link/button → fully covered.
				if ((it.tagName === 'A' && it.getAttribute('href')) || it.matches('[role="link"], button, [role="button"]')) { covs.push(1); continue; }
				// Otherwise: the biggest link inside covers how much of the row?
				let best = 0;
				for (const a of it.querySelectorAll('a[href], button, [role="button"], [role="link"]')) {
					const ar = a.getBoundingClientRect();
					// A target that spans (nearly) the full ROW WIDTH at a tappable height is a real
					// "click anywhere across the row" affordance even when it's shorter than a tall
					// COMPOSITE row — e.g. a card whose full-width summary opens a detail view with a
					// secondary disclosure/feedback strip stacked below it. That is NOT the bug this
					// lint hunts (there only a NARROW inner link, like the date, navigates), so an
					// area ratio would falsely read the tall card as "22% clickable". Count a
					// full-width, tappable target as covering the row.
					const fullWidth = ir.width > 0 && ar.width / ir.width >= 0.9 && ar.height >= 24;
					best = Math.max(best, fullWidth ? 1 : Math.min(1, (ar.width * ar.height) / area));
				}
				covs.push(best);
			}
			if (covs.length) {
				covs.sort((a, b) => a - b);
				listRowLinkCoverage = covs[Math.floor(covs.length / 2)]; // median
			}
		}
	} catch (_) { /* ignore */ }

	// Panel consistency: what fraction of a page's content sections sit inside a card/panel? A page
	// whose sections are bare while the rest of the site cards them reads as off-pattern / unfinished.
	// Measured over the content headings (h2/h3/role=heading in main, excluding the page h1): is each
	// wrapped by a visually-distinct container (border / radius / fill / shadow) before we reach main?
	let headingCount = 0;
	let headingPanelRatio = 1;
	try {
		const main = document.querySelector('main') || document.body;
		let inPanel = 0;
		for (const h of main.querySelectorAll('h2, h3, [role="heading"]')) {
			const r = h.getBoundingClientRect();
			if (r.width < 1 || r.height < 1) continue; // visible headings only
			headingCount++;
			let carded = false;
			for (let p = h.parentElement; p && p !== main && p !== document.body; p = p.parentElement) {
				const cs = getComputedStyle(p);
				const bw = cs.borderTopStyle !== 'none' ? parseFloat(cs.borderTopWidth) || 0 : 0;
				const rad = parseFloat(cs.borderTopLeftRadius) || 0;
				const bg = parseColor(cs.backgroundColor);
				const shadow = cs.boxShadow && cs.boxShadow !== 'none';
				if (bw >= 1 || rad >= 6 || (bg && bg.a > 0.1) || shadow) { carded = true; break; }
			}
			if (carded) inPanel++;
		}
		if (headingCount > 0) headingPanelRatio = Math.round((inPanel / headingCount) * 100) / 100;
	} catch (_) { /* ignore */ }

	// A MANAGED-ENTITY index: >=3 same-signature non-chrome siblings whose items mostly link into a
	// deeper route (/{parent}/{id}) — a list of things you drill into (sites, reports, members),
	// distinct from a big uniform pile (collectionMax). Feeds collection-no-create.
	let entityIndex = false;
	// Which route do the listed items LIVE under — "/sites" for a list of /sites/{id} cards? An index
	// OWNS its collection (the route it lists into is its own); a dashboard merely SURFACES items owned
	// elsewhere (recent /r/{id} reports), and it is not the dashboard's job to create those. Modal
	// value across the drilled items, null when they don't agree. Feeds collection-no-create.
	let entityIndexRoot = null;
	try {
		const deep = (a) => {
			const h = (a.getAttribute('href') || '').split(/[?#]/)[0];
			return h.startsWith('/') && !h.startsWith('//') && h.split('/').filter(Boolean).length >= 2;
		};
		const rootOf = (a) => {
			const segs = (a.getAttribute('href') || '').split(/[?#]/)[0].split('/').filter(Boolean);
			return segs.length >= 2 ? '/' + segs.slice(0, -1).join('/') : null;
		};
		for (const parent of document.querySelectorAll('ul,ol,[role="list"],[class*="grid" i],[class*="list" i]')) {
			if (parent.closest('nav,footer,[role=navigation],[role=menu],[role=tablist]')) continue;
			const kids = Array.from(parent.children).filter((k) => !['SCRIPT', 'STYLE', 'TEMPLATE', 'BR'].includes(k.tagName));
			if (kids.length < 3) continue;
			const sig = (k) => k.tagName + '.' + ((k.getAttribute('class') || '').trim().split(/\s+/)[0] || '');
			const s0 = sig(kids[0]);
			const same = kids.filter((k) => sig(k) === s0).length;
			if (same < 3 || same < kids.length * 0.6) continue;
			const links = kids
				.map((k) => (k.matches('a[href]') ? k : k.querySelector('a[href]')))
				.filter((a) => a && deep(a));
			const drill = links.length;
			if (drill >= 3 && drill >= same * 0.5) {
				entityIndex = true;
				const tally = new Map();
				for (const a of links) {
					const r = rootOf(a);
					if (r) tally.set(r, (tally.get(r) || 0) + 1);
				}
				const top = [...tally.entries()].sort((x, y) => y[1] - x[1])[0];
				// Only trust a root the majority of the items agree on — a mixed list (a dashboard's
				// audits AND invites) has no single home, and an unsure root must not gate a finding.
				entityIndexRoot = top && top[1] >= drill * 0.5 ? top[0] : null;
				break;
			}
		}
	} catch (_) { /* ignore */ }

	// A create affordance: a control/link that starts a "new X" flow (New/Add/Create or a link to
	// a */new|*/create route). Short labels only, chrome-excluded, so "New in v2" prose doesn't hit.
	let hasCreate = false;
	try {
		const CREATE = /\b(new|add|create)\b/i;
		for (const el of document.querySelectorAll('a[href],button,[role=button],[role=link],summary')) {
			if (el.closest('footer') || el.offsetParent === null) continue;
			const lbl = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim(); // accessible name: aria-label wins over text (concatenating doubled a labelled "Create X" past the length cap)
			const href = el.getAttribute('href') || '';
			// A leading + / ＋ is a create affordance too ("+ New", "+ Run an audit"), as is a
			// link to a */new|*/create route.
			if ((CREATE.test(lbl) && lbl.length <= 24) || (/^[+＋]/.test(lbl) && lbl.length <= 30) || /\/(new|create)(\/|$)/.test(href)) {
				hasCreate = true;
				break;
			}
		}
	} catch (_) { /* ignore */ }

	// EMPTY-DATA STATE: is this page showing "there's nothing here yet" rather than a populated list?
	// Deterministic + conservative, so a wrong guess only causes a MISSED finding (never a false one):
	// only when there is NO sizeable collection (collectionMax < 3) AND main holds a recognizable
	// empty-state block — an element whose class marks it empty (`empty`/`empty-state`/`no-results`,
	// word-bounded so "employee" doesn't match), or short copy that plainly says the collection is
	// empty ("No sites yet", "You don't have any…", "Nothing here yet"). Feeds empty-state-no-cta.
	let emptyState = false;
	// The empty block STRANDED at the top of a tall viewport: a small panel anchored high with a
	// big void beneath it and clearly more emptiness below than above — the "pinned to the top"
	// look. A vertically-centred (balanced) empty state, or an inline section-empty with content
	// below it, won't trip this. Feeds empty-state-stranded.
	let emptyStranded = false;
	let emptyStrandedRect = null;
	try {
		if (collectionMax < 3) {
			const main = document.querySelector('main, [role="main"]') || document.body;
			const EMPTY_TXT = /\b(no|nothing|zero)\b[^.!?]{0,40}\b(yet|here|found|results?|items?|sites?|reports?|projects?|entries|records?)\b|you (don'?t|do not) have any|nothing (to show|here yet)|get started by (adding|creating)/i;
			const EMPTY_CLS = /\bempty\b|empty-state|empty-card|no-results|no-data|placeholder-empty/i;
			for (const el of main.querySelectorAll('[class],[data-empty],[role="status"]')) {
				if (el.offsetParent === null) continue;
				const cls = (el.getAttribute('class') || '');
				const txt = (el.textContent || '').replace(/\s+/g, ' ').trim();
				if (!txt || txt.length > 320) continue; // a whole-page container isn't the empty block
				// A page HEADER (an <h1>, or the block wrapping it) is the page TITLE, never a zero-data
				// placeholder — even when its wording matches the empty-copy pattern (e.g. a docs h1
				// "From nothing to your first report" trips `nothing…report`). This is more robust than the
				// content-below guard below, which an SPA can defeat by rendering the header before the body.
				if (el.tagName === 'H1' || el.querySelector('h1')) continue;
				if (EMPTY_CLS.test(cls) || el.hasAttribute('data-empty') || EMPTY_TXT.test(txt)) {
					emptyState = true;
					try {
						const r = el.getBoundingClientRect();
						const vh = window.innerHeight || document.documentElement.clientHeight || 0;
						const above = r.top; // viewport top → block top
						const below = vh - r.bottom; // block bottom → viewport bottom
						// A genuinely stranded empty state has NOTHING beneath it. If `main` carries real
						// content below the block, it's a normal page whose text merely happens to match the
						// empty-copy pattern (e.g. the heading "From nothing to your first report") — not a
						// zero-data screen. Guard against that first: the void below must actually be void.
						let contentBelow = false;
						for (const c of main.querySelectorAll('h2,h3,p,li,section,table,img,form,pre,figure')) {
							if (c.offsetParent === null || el.contains(c)) continue;
							const cr = c.getBoundingClientRect();
							if (cr.top >= r.bottom - 2 && cr.height >= 16 && (c.textContent || '').trim().length > 0) { contentBelow = true; break; }
						}
						// Modest block, anchored in the top quarter, with a void below that dwarfs the
						// block, exceeds a quarter-viewport, and clearly out-weighs the space above.
						if (!contentBelow && vh > 0 && r.height > 0 && r.height < vh * 0.6 && r.top < vh * 0.25 &&
							below > r.height && below > vh * 0.25 && below > above * 1.5) {
							emptyStranded = true;
							emptyStrandedRect = [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)];
						}
					} catch (_) { /* ignore */ }
					break;
				}
			}
		}
	} catch (_) { /* ignore */ }

	// SVG DIAGRAM LABELS off-centre in their box — the diagram equivalent of off-center-content,
	// which only ever sees HTML text (it can't reach into an inline <svg>). For each filled/bordered
	// <rect> that reads as a label box, GROUP every <text> that sits inside it (a multi-line label is
	// several <text> elements, so we judge the whole BLOCK, not each line) and compare the block's
	// centre to the box's centre. Conservative — a text touching an edge (overflow / an arrow label
	// beside a box) is skipped, each text is tied to its SMALLEST containing box (so a label centred
	// in an inner box isn't judged against an outer one), and the offset must clearly beat a rounding
	// wobble (>6px AND >15% of the half-dimension). Emits the boxes that fail, worst first.
	let svgOffCenterLabels = [];
	try {
		const near = (el) => el.getBoundingClientRect();
		for (const svg of document.querySelectorAll('svg')) {
			const sb = near(svg);
			if (sb.width < 2 || sb.height < 2) continue; // not rendered
			const boxes = [...svg.querySelectorAll('rect')]
				.map((r) => ({ bb: near(r) }))
				.filter(({ bb }, i) => {
					const r = svg.querySelectorAll('rect')[i];
					const cs = getComputedStyle(r);
					const filled = cs.fill && cs.fill !== 'none' && !/rgba?\([^)]*,\s*0\)\s*$/.test(cs.fill);
					const stroked = cs.stroke && cs.stroke !== 'none' && (parseFloat(cs.strokeWidth) || 0) > 0;
					// a real label box: painted, sized, and not the whole-svg background
					return (filled || stroked) && bb.width >= 30 && bb.height >= 24 &&
						!(bb.width > sb.width * 0.95 && bb.height > sb.height * 0.95);
				});
			if (!boxes.length) continue;
			const texts = [...svg.querySelectorAll('text')]
				.map((t) => ({ tb: near(t), txt: (t.textContent || '').trim() }))
				.filter(({ tb, txt }) => txt && tb.width >= 1 && tb.height >= 1);
			// Tie each text to the SMALLEST box that contains it.
			const groups = new Map();
			for (const { tb } of texts) {
				let best = -1, bestArea = Infinity;
				boxes.forEach(({ bb }, i) => {
					if (tb.left >= bb.left - 1 && tb.right <= bb.right + 1 && tb.top >= bb.top - 1 && tb.bottom <= bb.bottom + 1) {
						const area = bb.width * bb.height;
						if (area < bestArea) { bestArea = area; best = i; }
					}
				});
				if (best >= 0) {
					if (!groups.has(best)) groups.set(best, []);
					groups.get(best).push(tb);
				}
			}
			for (const [bi, tbs] of groups) {
				const bb = boxes[bi].bb;
				let l = Infinity, tp = Infinity, rt = -Infinity, bt = -Infinity;
				for (const tb of tbs) { l = Math.min(l, tb.left); tp = Math.min(tp, tb.top); rt = Math.max(rt, tb.right); bt = Math.max(bt, tb.bottom); }
				// The block must leave margin on every side — text touching an edge is overflow/anchoring,
				// a different problem, not a centring call.
				if (Math.min(l - bb.left, bb.right - rt) < 2 || Math.min(tp - bb.top, bb.bottom - bt) < 2) continue;
				const dx = (l + rt) / 2 - (bb.left + bb.right) / 2;
				const dy = (tp + bt) / 2 - (bb.top + bb.bottom) / 2;
				const badX = Math.abs(dx) > 6 && Math.abs(dx) / (bb.width / 2) > 0.15;
				const badY = Math.abs(dy) > 6 && Math.abs(dy) / (bb.height / 2) > 0.15;
				if (badX || badY) {
					svgOffCenterLabels.push({
						rect: [Math.round(bb.left), Math.round(bb.top), Math.round(bb.width), Math.round(bb.height)],
						dx: Math.round(dx),
						dy: Math.round(dy)
					});
				}
			}
		}
		svgOffCenterLabels.sort((a, b) => Math.max(Math.abs(b.dx), Math.abs(b.dy)) - Math.max(Math.abs(a.dx), Math.abs(a.dy)));
		svgOffCenterLabels = svgOffCenterLabels.slice(0, 5);
	} catch (_) { /* ignore */ }

	// A framed diagram whose DRAWN CONTENT isn't centred in its own viewBox — the whole graphic sits
	// low/high (or left/right), so one margin dwarfs the opposite one and it reads as unbalanced. This
	// is the whole-diagram cousin of svg-off-center-labels (which judges a label inside one box); here
	// we judge every drawn child against the svg's frame. We only MEASURE the four margins here — the
	// fire/clean threshold lives in the Rust lint so it's unit-testable. Scoped to real framed diagrams
	// (role="img"/aria-label, sized, ≥2 drawn parts, content fully inside the frame) so icons and
	// decorative glyphs never qualify.
	let svgUnbalanced = [];
	try {
		for (const svg of document.querySelectorAll('svg[role="img"], svg[aria-label]')) {
			const sb = svg.getBoundingClientRect();
			if (sb.width < 160 || sb.height < 60) continue; // an icon, not a framed diagram
			let l = Infinity, t = Infinity, r = -Infinity, b = -Infinity, n = 0;
			for (const el of svg.querySelectorAll('rect,circle,ellipse,line,polyline,polygon,path,text')) {
				if (el.closest('defs,marker,symbol,clipPath,mask')) continue; // template/offscreen defs
				const bb = el.getBoundingClientRect();
				if (bb.width < 0.5 && bb.height < 0.5) continue; // not rendered
				if (bb.width > sb.width * 0.95 && bb.height > sb.height * 0.95) continue; // the frame/background itself
				l = Math.min(l, bb.left); t = Math.min(t, bb.top); r = Math.max(r, bb.right); b = Math.max(b, bb.bottom); n++;
			}
			if (n < 2 || !isFinite(l)) continue; // need real multi-part content
			const mL = l - sb.left, mR = sb.right - r, mT = t - sb.top, mB = sb.bottom - b;
			if (mL < -1 || mR < -1 || mT < -1 || mB < -1) continue; // content overflows the frame — a different problem
			svgUnbalanced.push({
				rect: [Math.round(sb.left), Math.round(sb.top), Math.round(sb.width), Math.round(sb.height)],
				mT: Math.round(mT), mB: Math.round(mB), mL: Math.round(mL), mR: Math.round(mR)
			});
		}
		svgUnbalanced = svgUnbalanced.slice(0, 8);
	} catch (_) { /* ignore */ }

	// A framed diagram <svg> that HARDCODES its colours — fill/stroke committed as hex/rgb/named right
	// on the shapes — instead of driving them from the theme (currentColor / CSS custom properties /
	// a gradient ref). On a themed site such a diagram ignores the design tokens and won't adapt to
	// dark mode. We only TALLY per diagram here; the fire threshold + the themed-page gate live in the
	// Rust lint. Same diagram scope as svgUnbalanced (role/aria + sized) so icons never qualify, and a
	// colour is counted only when it's authored ON the element — a fill that comes from a CSS
	// stylesheet is the tokenizable path already and is never held against the diagram.
	let svgUntokenized = [];
	try {
		// Classify an authored fill/stroke value: null = ignore (unset), '' = responsive (tracks the
		// theme), else the lowercased literal colour string (a committed hex/rgb()/named colour).
		const litOf = (v) => {
			if (!v) return null;
			const s = ('' + v).trim().toLowerCase();
			if (!s) return null;
			if (s === 'none' || s === 'transparent' || s === 'currentcolor' || s === 'inherit' ||
				s === 'context-fill' || s === 'context-stroke' || s.startsWith('var(') || s.startsWith('url(')) return '';
			return s;
		};
		for (const svg of document.querySelectorAll('svg[role="img"], svg[aria-label]')) {
			const sb = svg.getBoundingClientRect();
			if (sb.width < 160 || sb.height < 60) continue; // an icon, not a framed diagram
			let literal = 0, responsive = 0; const lits = new Set();
			for (const el of svg.querySelectorAll('rect,circle,ellipse,line,polyline,polygon,path')) {
				if (el.closest('defs,marker,symbol,clipPath,mask')) continue; // template/offscreen defs
				const bb = el.getBoundingClientRect();
				if (bb.width < 0.5 && bb.height < 0.5) continue; // not rendered
				for (const prop of ['fill', 'stroke']) {
					const authored = el.getAttribute(prop) || (el.style && el.style[prop]) || '';
					const lit = litOf(authored);
					if (lit === null) continue; // colour comes from CSS — the tokenizable path, uncounted
					if (lit === '') responsive++;
					else { literal++; lits.add(lit); }
				}
			}
			if (literal + responsive === 0) continue; // all colours come from CSS — nothing to say
			svgUntokenized.push({
				rect: [Math.round(sb.left), Math.round(sb.top), Math.round(sb.width), Math.round(sb.height)],
				literal, responsive, distinctLiterals: lits.size
			});
		}
		svgUntokenized = svgUntokenized.slice(0, 8);
	} catch (_) { /* ignore */ }

	// A secret shown on screen with NO copy affordance beside it — users hand-select a long
	// random string and drop characters, then hit a baffling auth failure. Match unambiguous
	// key/token shapes (real random tail, so `uxr_…` placeholders in docs don't hit).
	let secretNoCopy = false;
	try {
		const SECRET = /(uxr_|uxt_|sk-|sk_|ghp_|gho_|github_pat_|xox[baprs]-|AIza|glpat-)[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}/;
		for (const el of document.querySelectorAll('code, kbd, samp, input, [class*="token" i], [class*="secret" i], [class*="apikey" i], [class*="api-key" i]')) {
			if (el.children.length > 2) continue; // leaf-ish holder
			// A key shown inside a quotation or an explicitly-marked example is documentation of a
			// secret's shape, not a live secret the user must copy. (Bare <code> is NOT exempt —
			// that's exactly where a real displayed key lives.)
			if (el.closest('blockquote,q,[data-example],[data-uxlint-example]')) continue;
			const txt = (el.tagName === 'INPUT' ? el.value || el.getAttribute('value') || '' : el.textContent || '').trim();
			if (!SECRET.test(txt)) continue;
			const r = el.getBoundingClientRect();
			if (r.width < 4 || el.offsetParent === null) continue;
			// A Copy control anywhere in the secret's immediate container counts as handled.
			const scope = el.closest('div,li,section,form,td,tr,pre') || el.parentElement || el;
			const hasCopy = Array.from(scope.querySelectorAll('button,[role="button"],a,[aria-label]')).some((c) =>
				/copy/i.test((c.getAttribute('aria-label') || '') + ' ' + (c.textContent || '') + ' ' + (c.className || ''))
			);
			if (!hasCopy) { secretNoCopy = true; break; }
		}
	} catch (_) { /* ignore */ }

	// Pagination: a pager means the full dataset spills past this page, so the visible slice
	// undercounts the real collection — search matters even when few items show at once.
	let paginated = false;
	try {
		if (document.querySelector(
			'a[rel=next],a[rel=prev],link[rel=next],[class*="paginat" i],[class*="pager" i],' +
			// `pagination`, NOT `page` — a bare "page" matched an "On this page" TOC nav, mis-reading a
			// docs reference page as a paginated collection (dogfood FP on /docs/cli's searchability).
			'[aria-label*="pagination" i],nav[aria-label*="pagination" i]'
		)) {
			paginated = true;
		}
		if (!paginated) {
			// aria-labelled / textual next-prev-page controls
			for (const el of document.querySelectorAll('a,button,[role=button],[role=link]')) {
				const lbl = ((el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '')).toLowerCase().trim();
				if (/\b(next|previous|prev)\s+page\b/.test(lbl) || /^page\s+\d+\b/.test(lbl)) { paginated = true; break; }
			}
		}
		if (!paginated) {
			// A small container whose direct children are page numbers (1, 2, 3, …). "Numeric
			// children" ALONE is far too loose — a deck list's quantity column, a scoreboard, a
			// calendar and a table of counts all match it, and one such page was reported from the
			// field as "a paginated collection with more behind the pager" when the page had no pager
			// at all. A real pager has two more properties: its numbers are CLICKABLE, and they ASCEND
			// CONSECUTIVELY. Require both. (Clickable allows one exception — the current page is
			// usually rendered as plain text.)
			for (const parent of document.querySelectorAll('ul,ol,nav,div')) {
				const kids = parent.children;
				if (kids.length < 4 || kids.length > 40) continue;
				const seq = [];
				let clickable = 0;
				for (const k of kids) {
					const t = (k.textContent || '').trim();
					if (!/^\d{1,3}$/.test(t)) continue;
					seq.push(+t);
					if (k.matches('a,button,[role=button],[role=link]') || k.querySelector('a,button,[role=button],[role=link]')) clickable++;
				}
				if (seq.length < 4 || clickable < seq.length - 1) continue;
				let consecutive = true;
				for (let i = 1; i < seq.length; i++) {
					if (seq[i] !== seq[i - 1] + 1) { consecutive = false; break; }
				}
				if (consecutive) { paginated = true; break; }
			}
		}
	} catch (_) { /* ignore */ }

	// ── Manual/AI parity: is content produced ONLY by AI, with no way to author it by hand? ──
	// Every generative action should have a manual twin. Count AI-generation controls vs. the
	// hand-authoring affordances on the page (text fields, contenteditable, explicit Edit).
	let aiGenControls = 0;
	let manualEditControls = 0;
	try {
		// STRONG evidence of generation: a verb that only means "the machine makes this", or a wand/
		// robot glyph. WEAK: the bare words "ai" and "magic", which collide with ordinary product
		// language — "magic link" sign-in, "Magic: The Gathering", a set or product name that happens
		// to contain them. A weak match is counted ONLY on a page that also shows strong evidence, so
		// the rule never fires on vocabulary alone. Reported from the field: three buttons on a
		// card-game page were read as AI-generation controls on a page with no generated content
		// anywhere, and the finding asked the author to add hand-authoring to a workflow that was
		// already entirely by hand.
		const AI_STRONG = /\b(generate|regenerate|auto[- ]?generate|rewrite|co[- ]?write|ai[- ]?(write|assist|generated?)|magic[- ](write|edit|fill|compose|eraser))\b/i;
		const AI_WEAK = /\b(ai|magic)\b/i;
		const AI_GLYPH = /[✨\u{1FA84}\u{1F916}\u{1F9E0}]/u; // ✨ 🪄 🤖 🧠
		let strongHits = 0;
		let weakHits = 0;
		for (const el of document.querySelectorAll('button,a,[role=button],input[type=submit]')) {
			const raw = (el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '');
			const name = raw.replace(/\s+/g, ' ').trim();
			if (AI_GLYPH.test(raw) || AI_STRONG.test(name)) strongHits++;
			else if (AI_WEAK.test(name)) weakHits++;
		}
		aiGenControls = strongHits + (strongHits > 0 ? weakHits : 0);
		// Hand-authoring affordances: text fields (not search/toggle/button), contenteditable,
		// textbox role, or an explicit Edit/rename/write-your-own control.
		const authoring = document.querySelectorAll(
			'textarea,[contenteditable=""],[contenteditable="true"],[role=textbox],' +
			'input:not([type=search]):not([type=checkbox]):not([type=radio]):not([type=submit]):not([type=button]):not([type=range]):not([type=file]):not([type=color])'
		).length;
		let editControls = 0;
		for (const el of document.querySelectorAll('button,a,[role=button]')) {
			const name = ((el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '')).toLowerCase();
			if (/\b(edit|rename|write your own|add manually|customi[sz]e)\b/.test(name)) editControls++;
		}
		manualEditControls = authoring + editControls;
	} catch (_) { /* ignore */ }

	// Account view: affordances that only appear on a signed-in / private page. Drives the
	// signed-out-gating lint — a private page should redirect signed-out visitors, not strand
	// them on a dead "not signed in" panel. Scan controls / headings / labels, not body prose.
	let authAffordances = [];
	try {
		const names = [];
		for (const el of document.querySelectorAll(
			'button,a,[role=button],h1,h2,h3,summary,label,legend,dt,th'
		)) {
			// Page CONTENT only — a "Sign out" in the shared nav/header is site chrome present on
			// every page; it must not mark public pages (landing, docs) as private views.
			if (el.closest('nav,header,footer,[role=navigation],[role=banner],[role=contentinfo]'))
				continue;
			const t = ((el.getAttribute('aria-label') || '') + ' ' + (el.textContent || ''))
				.replace(/\s+/g, ' ')
				.trim()
				.toLowerCase();
			if (t) names.push(t);
		}
		const any = (re) => names.some((t) => re.test(t));
		if (any(/\b(sign out|log ?out)\b/)) authAffordances.push('sign-out');
		if (any(/(rotate|regenerate|reveal|copy)\b[^.]{0,20}\bkey\b|\byour api key\b/))
			authAffordances.push('api-key');
		if (any(/\b(members?|invite|your orgs?|my orgs?|team members?)\b/)) authAffordances.push('org');
		// Bare "billing" appears in legal/pricing prose headings — require the stronger,
		// unmistakably-account markers.
		if (any(/\b(usage this month|audits this month|reports this month|billing history|manage subscription|payment method|your plan)\b/))
			authAffordances.push('billing');
		// A masked secret field that is NOT a login password (no sign-in language on the page).
		const pw = document.querySelector('input[type=password]');
		const bodyTxt = ((document.body && document.body.innerText) || '').slice(0, 1500).toLowerCase();
		if (pw && !/\b(sign in|log ?in|password|forgot)\b/.test(bodyTxt))
			authAffordances.push('secret-field');
	} catch (_) {
		/* ignore */
	}

	// Copyable code: a code snippet (<pre>) users are meant to copy — install commands, config,
	// examples — should offer a copy control, or they hand-select and miss characters.
	let codeBlocks = 0;
	let codeBlocksNoCopy = 0;
	try {
		for (const pre of document.querySelectorAll('pre')) {
			const text = (pre.innerText || '').trim();
			if (text.length < 40) continue; // skip trivial / inline snippets
			codeBlocks++;
			// A copy control inside the block or its immediate wrapper.
			const scope =
				pre.closest('figure,[class*="code" i],[class*="snippet" i],[class*="highlight" i]') ||
				pre.parentElement ||
				pre;
			let hasCopy = false;
			for (const el of scope.querySelectorAll('button,[role="button"],a,[class*="copy" i]')) {
				const name = (
					(el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '') + ' ' +
					(el.getAttribute('title') || '') + ' ' + (el.getAttribute('class') || '')
				).toLowerCase();
				if (/copy|clipboard|📋/.test(name)) {
					hasCopy = true;
					break;
				}
			}
			if (!hasCopy) codeBlocksNoCopy++;
		}
	} catch (_) {
		/* ignore */
	}

	// Head signals for shareability: search snippet, social-card tags, tab icon.
	// `ogImage` is separate from the ogTags COUNT on purpose. og:image is the one tag that decides
	// whether a pasted link renders as a CARD or as a line of text, and a page can carry og:type,
	// og:title and og:description — a count of three, which passes any "has og tags?" test — while
	// unfurling as nothing at all. That was uxlint's own home page.
	let metaDescription = false;
	let ogTags = 0;
	let ogImage = false;
	let iconLink = false;
	try {
		metaDescription = !!document.querySelector('meta[name="description"][content]');
		ogTags = document.querySelectorAll('meta[property^="og:"]').length;
		ogImage = !!document.querySelector('meta[property="og:image"][content], meta[name="twitter:image"][content]');
		iconLink = !!document.querySelector('link[rel~="icon" i], link[rel="apple-touch-icon"]');
	} catch (_) {
		/* ignore */
	}

	// Document language (WCAG 3.1.1): a missing/empty <html lang> makes screen readers
	// mispronounce and breaks browser translation. Report the raw value; the lint judges it.
	const htmlLang = (document.documentElement.getAttribute('lang') || '').trim();

	// Stale-copyright signal: the newest year in a footer/body copyright line, plus the page's
	// OWN clock (the browser's) so the lint compares against the user's real "now", not the
	// server's. A footer stuck years in the past reads as an abandoned site.
	let copyrightYear = 0, pageYear = 0;
	try {
		pageYear = new Date().getFullYear();
		// ONLY short copyright-notice lines (dateMarkers, < 80 chars) — never a "copyright"
		// mentioned in prose (e.g. a report that DISPLAYS a finding about a stale footer). The
		// year must sit tight after ©/copyright, so "copyright says 2019" in a sentence won't hit.
		for (const dm of dateMarkers) {
			const m = dm.match(/(?:©|\(c\)|copyright)\s*[^\d]{0,10}?((?:19|20)\d{2})(?:\s*[–—-]\s*((?:19|20)\d{2}))?/i);
			if (m) copyrightYear = Math.max(copyrightYear, parseInt(m[2] || m[1], 10));
		}
	} catch (_) { /* ignore */ }

	// Generic submit labels (NN/g): a form's submit button labelled "Submit"/"Send"/"OK" names
	// no outcome. Action-specific labels ("Create account", "Send message") tell users what
	// happens. Only genuine submit controls, visible.
	const GENERIC_SUBMIT = /^(submit|send|ok(ay)?|go|proceed|continue)$/i;
	let genericSubmitLabels = [];
	try {
		const btns = document.querySelectorAll('form button:not([type=button]):not([type=reset]), form [role=button], button[type=submit], input[type=submit], input[type=button]');
		for (const b of btns) {
			const r = b.getBoundingClientRect();
			if (r.width < 4 || r.height < 4 || b.offsetParent === null) continue;
			const name = ((b.getAttribute('aria-label') || '') || (b.tagName === 'INPUT' ? (b.value || '') : (b.textContent || ''))).replace(/\s+/g, ' ').trim();
			if (GENERIC_SUBMIT.test(name) && genericSubmitLabels.length < 6) genericSubmitLabels.push(name.slice(0, 20));
		}
	} catch (_) { /* ignore */ }

	// Multi-column form (Baymard): text fields spread across two or more columns break the
	// vertical scan and get skipped. Count columns that each hold ≥2 fields, on the biggest
	// form — a single side-by-side "First / Last" row (one 2-field row) is NOT flagged.
	let formColumns = 0;
	try {
		const fsel = 'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]), select, textarea';
		let best = null, bn = 0;
		for (const fm of document.querySelectorAll('form')) { const n = fm.querySelectorAll(fsel).length; if (n > bn) { bn = n; best = fm; } }
		if (best && bn >= 5) {
			const xs = [];
			best.querySelectorAll(fsel).forEach(fl => { const r = fl.getBoundingClientRect(); if (r.width > 4 && fl.offsetParent !== null) xs.push(Math.round(r.left)); });
			const clusters = [];
			for (const x of xs.sort((a, b) => a - b)) { let c = clusters.find(c => Math.abs(c.x - x) <= 60); if (!c) { c = { x, count: 0 }; clusters.push(c); } c.count++; }
			formColumns = clusters.filter(c => c.count >= 2).length;
		}
	} catch (_) { /* ignore */ }

	// Link distinguished by colour alone (WCAG 1.4.1): an inline prose link with no underline,
	// no bold, no button styling, whose colour contrast against the surrounding body text is
	// under 3:1 — colour-blind users can't tell it's a link. Reuses parseColor.
	let linkColorOnly = [];
	let linkColorOnlyRect = null; // rect of the FIRST offending link — anchors the report crop + fix preview
	let linkColorOnlyRects = []; // every offending link, for a multi-box mark-up
	try {
		const relLum = (c) => { const s = [c.r, c.g, c.b].map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * s[0] + 0.7152 * s[1] + 0.0722 * s[2]; };
		const ratio = (a, b) => { const l1 = relLum(a), l2 = relLum(b), hi = Math.max(l1, l2), lo = Math.min(l1, l2); return (hi + 0.05) / (lo + 0.05); };
			// A link needn't be underlined at rest if it changes on hover (Google-style): scan the
			// stylesheets for a :hover rule matching it that flips decoration / colour / background.
			const hoverChanges = (el) => {
				try {
					for (const sheet of document.styleSheets) {
						let rules; try { rules = sheet.cssRules; } catch (e) { continue; }
						if (!rules) continue;
						for (const rule of rules) {
							if (!rule.selectorText || rule.selectorText.indexOf(':hover') < 0) continue;
							const base = rule.selectorText.replace(/:hover/g, '').trim();
							if (!base) continue;
							let m = false; try { m = el.matches(base); } catch (e) {}
							if (!m) continue;
							const st = rule.style;
							if (st.textDecoration || st.textDecorationLine || st.color || st.backgroundColor || st.background || st.borderBottomWidth) return true;
						}
					}
				} catch (e) {}
				return false;
			};
		for (const a of document.querySelectorAll('p a[href], li a[href], td a[href], dd a[href], span a[href]')) {
			const r = a.getBoundingClientRect();
			if (r.width < 4 || r.height < 4 || a.offsetParent === null) continue;
			if (a.closest('nav,[role="navigation"]')) continue; // nav items stand out by POSITION — colour-only is fine there
			if (hoverChanges(a)) continue; // underlines/changes on hover (Google-style) — acceptable
			const cs = getComputedStyle(a);
			// WCAG 1.4.1 is about links set in a RUN OF PROSE. A whole clickable card/row (a
			// block link wrapping a heading + meta lines, e.g. "example.com · 17 audits · last…")
			// is not inline prose — it stands out by its box, not colour. Skip anything that
			// isn't a genuine inline link: block/flex display, or a link that wraps block content.
			if (!/^inline/.test(cs.display)) continue;
			if (a.querySelector('div,section,article,header,footer,ul,ol,li,table,figure,img,p,h1,h2,h3,h4,h5,h6')) continue;
			const fs = parseFloat(cs.fontSize) || 16;
			if (r.height > fs * 2.4) continue; // taller than a wrapped line-pair → a card, not a link
			if (cs.textDecorationLine.includes('underline') || (parseInt(cs.fontWeight) || 400) >= 600) continue; // has a non-colour cue
			const abg = parseColor(cs.backgroundColor);
			if ((abg && abg.a > 0.1) || parseFloat(cs.borderBottomWidth) > 0 || parseFloat(cs.borderTopWidth) > 0 || parseFloat(cs.paddingLeft) >= 6) continue; // styled like a button/tag
			const parent = a.parentElement; if (!parent) continue;
			const lc = parseColor(cs.color), pc = parseColor(getComputedStyle(parent).color);
			if (!lc || !pc) continue;
			if (ratio(lc, pc) < 3.0 && linkColorOnly.length < 6) {
				const lr = [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)];
				if (!linkColorOnlyRect) linkColorOnlyRect = lr;
				linkColorOnlyRects.push(lr);
				linkColorOnly.push((a.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 30));
			}
		}
	} catch (_) { /* ignore */ }

	// Layout width strategy: data-dense content (a table/grid) being squeezed for width WHILE
	// there's empty screen beside it — the tell that a centered layout is wrong for this view
	// and it should go full-width (usually with a side nav). dataCramped = such a container
	// exists; wastedSideFrac = the empty fraction on the narrower side when it does.
	let dataCramped = false, wastedSideFrac = 0;
	try {
		for (const t of document.querySelectorAll('table, [role="grid"], [role="table"], [role="treegrid"]')) {
			const r = t.getBoundingClientRect();
			if (r.width < vw * 0.3 || r.height < 60 || t.offsetParent === null) continue; // small widget, not the main data
			// The overflow usually lives on a scroll WRAPPER around the table (overflow-x:auto),
			// not the table element itself. Walk up a few levels to find the clipped container —
			// its rect is the visible data column, which is what we measure side-room against.
			let node = t, clip = null;
			for (let k = 0; k < 3 && node; k++) {
				if (node.scrollWidth > node.clientWidth + 8) { clip = node; break; }
				node = node.parentElement;
			}
			if (!clip) continue; // table fits its column — not cramped
			const cr = clip.getBoundingClientRect();
			const room = Math.max(0, Math.min(cr.left, vw - cr.right)) / vw; // empty screen on the narrower side
			if (room >= 0.1) { dataCramped = true; wastedSideFrac = Math.round(room * 100) / 100; break; }
		}
	} catch (_) { /* ignore */ }

	// i18n slack (the "German test", measured not injected): a nav/toolbar row whose nowrap
	// labels already fill it has no room for +30% translation growth. Canvas-measure the
	// glyph width of each label so the maths is layout-independent.
	let i18nRows = [];
	try {
		const seenRows = new Set();
		for (const root of document.querySelectorAll('nav, [role="navigation"], [role="menubar"], [role="tablist"], header')) {
			if (i18nRows.length >= 6) break;
			for (const row of [root, ...root.querySelectorAll('ul, ol, menu, div')]) {
				if (i18nRows.length >= 6) break;
				if (seenRows.has(row)) continue;
				const rcs = getComputedStyle(row);
				if (!rcs.display.includes('flex') || rcs.flexDirection.startsWith('column')) continue;
				if (rcs.flexWrap === 'wrap') continue; // wrapping rows absorb growth
				if (/(auto|scroll)/.test(rcs.overflowX)) continue; // scroll strips manage their own overflow
				const rr = row.getBoundingClientRect();
				if (rr.width < 320 || rr.height > 120 || rr.height < 8) continue;
				const kids = [];
				for (const k of row.children) {
					const kcs = getComputedStyle(k);
					// absolute/fixed children don't consume flex space — counting them inflates fullness
					if (kcs.display === 'none' || kcs.position === 'absolute' || kcs.position === 'fixed') continue;
					const kr = k.getBoundingClientRect();
					if (kr.width <= 0) continue;
					kids.push({ k, kr, kcs });
				}
				const labelled = kids.filter(({ k }) => (k.textContent || '').replace(/\s+/g, ' ').trim().length >= 2);
				if (labelled.length < 3) continue;
				let childrenW = 0;
				let textW = 0;
				for (const { k, kr, kcs } of kids) {
					const label = (k.textContent || '').replace(/\s+/g, ' ').trim();
					// An empty, growable element is a SPACER, not content — the two standard "push the CTA
					// to the right" idioms are a flex-grow spacer <span> and a margin-auto pusher, and in BOTH
					// the absorbed width is slack translated labels grow INTO, not fight. Counting it as
					// consumed made every spacer-justified nav look full and falsely fail the German test.
					// Drop the spacer's width, and drop an auto margin's resolved px off any child.
					const marginAuto = k.style.marginLeft === 'auto' || k.style.marginRight === 'auto';
					if (label.length < 2 && ((parseFloat(kcs.flexGrow) || 0) > 0 || marginAuto)) continue;
					childrenW += kr.width
						+ (k.style.marginLeft === 'auto' ? 0 : parseFloat(kcs.marginLeft) || 0)
						+ (k.style.marginRight === 'auto' ? 0 : parseFloat(kcs.marginRight) || 0);
					if (label && cctx) {
						try {
							cctx.font = `${kcs.fontWeight} ${kcs.fontSize} ${kcs.fontFamily}`;
							textW += cctx.measureText(label).width;
						} catch (_) { /* keep measuring the rest */ }
					}
				}
				const gapW = (parseFloat(rcs.columnGap) || 0) * Math.max(0, kids.length - 1);
				const innerW = row.clientWidth - (parseFloat(rcs.paddingLeft) || 0) - (parseFloat(rcs.paddingRight) || 0);
				seenRows.add(row);
				i18nRows.push({
					sel: shortSel(row),
					x: Math.round(rr.left), y: Math.round(rr.top),
					w: Math.round(rr.width), h: Math.round(rr.height),
					innerW: Math.round(innerW),
					childrenW: Math.round(childrenW),
					gapW: Math.round(gapW),
					textW: Math.round(textW),
					items: labelled.length
				});
			}
		}
	} catch (_) { /* ignore */ }

	// Signed-in chrome: a sign-out control ANYWHERE (incl. nav) marks this as an app view.
	let authChrome = false;
	try {
		authChrome = Array.from(document.querySelectorAll('button, a, [role="button"], summary'))
			.some(e => /\b(sign out|log ?out)\b/i.test((e.textContent || '') + ' ' + (e.getAttribute('aria-label') || '')));
	} catch (_) { /* ignore */ }

	// Primary navigation shape — for the nav-pattern (side vs top) and app-shell lints.
	// The primary nav is the visible <nav>/[role=navigation] with the most destinations.
	// orientation: 'side' (taller than wide, or column flex) vs 'top' (wider than tall).
	// contextSwitcher: a workspace/org/project picker (a select or a labelled switcher) that
	// wants to persist — a strong signal the app needs a side nav.
	let primaryNav = { present: false, orientation: '', dests: 0, contextSwitcher: false, acquisition: [], accountItems: [], accountItemRects: [], accountItemsBottom: false, userMenu: false, hasSideNav: false };
	try {
		// A BREADCRUMB is never the primary nav — it says where you ARE, not where you can go. This
		// matters most at mobile width, where it is often the only nav landmark still VISIBLE: the
		// real nav sits behind a hamburger (`display:none` until opened), so it fails the
		// offsetParent test below and the trail wins by default. Every consumer of primaryNav then
		// reasons about the wrong element. On our own app that surfaced as `settings-in-primary-nav`
		// firing on a "Settings" CRUMB, but any site whose nav is behind a toggle — i.e. most
		// responsive sites — would have had its whole mobile nav shape read off a breadcrumb.
		// Same selector the breadcrumb signal itself uses, so the two can't disagree about what one is.
		const isBreadcrumb = (n) =>
			n.matches('nav[aria-label*="breadcrumb" i], [class*="breadcrumb" i], [id*="breadcrumb" i], [aria-label*="breadcrumb" i]');
		const navs = Array.from(document.querySelectorAll('nav, [role="navigation"]')).filter(n => {
			if (isBreadcrumb(n)) return false;
			const r = n.getBoundingClientRect();
			return r.width > 4 && r.height > 4 && n.offsetParent !== null;
		});
		const destsOf = (n) => Array.from(n.querySelectorAll('a[href], button, [role="button"], [role="link"], [role="menuitem"], [role="tab"]'))
			.filter(e => {
				const r = e.getBoundingClientRect();
				return r.width > 4 && r.height > 4 && (e.textContent || '').trim().length >= 1;
			});
		let best = null, bestN = 0;
		for (const n of navs) { const d = destsOf(n).length; if (d > bestN) { bestN = d; best = n; } }
		// Does a real SIDE nav exist anywhere? An app can pair a top bar (profile, search,
		// notifications, create) WITH a left side nav — a common, correct pattern (Reddit,
		// Linear, GitHub). If a side nav is present, the top bar is utility chrome, not a
		// mis-chosen primary nav, so the side-vs-top lint must not fire.
		let hasSideNav = false;
		for (const n of navs) {
			if (destsOf(n).length < 4) continue;
			const rr = n.getBoundingClientRect();
			const ncs = getComputedStyle(n);
			const col = ncs.display.includes('flex') && ncs.flexDirection.startsWith('column');
			if (col || rr.height > rr.width * 1.5) { hasSideNav = true; break; }
		}
		if (best) {
			const r = best.getBoundingClientRect();
			const cs = getComputedStyle(best);
			const col = cs.display.includes('flex') && cs.flexDirection.startsWith('column');
			const orientation = (col || r.height > r.width * 1.5) ? 'side' : 'top';
			const dests = destsOf(best);
			// Acquisition affordances that should VANISH once signed in.
			const ACQ = /\b(sign ?up|log ?in|sign ?in|register|get started|start free|try free|book a demo|request a demo|pricing|see plans|buy now)\b/i;
			// An acquisition affordance is a link to a PUBLIC marketing page (/pricing, /signup,
			// /login). A signed-in nav item that merely shares one of these words but points DEEPER
			// into the app — an admin "Pricing" config at /dashboard/admin/pricing, an account
			// billing tool — is an internal control, not marketing bleed. Distinguish by href: drop
			// a link whose path dives ≥2 segments deep or sits under a known app-shell root.
			const APP_ROOT = /^(dashboard|app|admin|account|settings|portal|console)$/i;
			const acqLabel = e => ((e.getAttribute('aria-label') || '') + ' ' + (e.textContent || '')).replace(/\s+/g, ' ').trim();
			const inAppRoute = e => {
				const href = e.getAttribute('href') || '';
				if (!href || href.startsWith('#')) return false;
				let path = href;
				try { path = new URL(href, location.href).pathname; } catch (_) { /* keep raw */ }
				const segs = path.split('/').filter(Boolean);
				return segs.length >= 2 || APP_ROOT.test(segs[0] || '');
			};
			const acquisition = [...new Set(dests
				.filter(e => ACQ.test(acqLabel(e)) && !inAppRoute(e))
				.map(e => acqLabel(e).slice(0, 30)))].slice(0, 6);
			// Context switcher, detected STRUCTURALLY rather than by a keyword label: a <select> in the
			// nav or app-shell chrome whose options are entity INSTANCES — their values are id-like
			// (numeric, or a slug that also appears as a path segment in the page's links). That ties
			// the switcher to the app's routable entities (orgs/workspaces/projects); unlike matching
			// "workspace|org|team", it holds up under i18n and excludes enum pickers (theme, language)
			// whose option values aren't routes.
			const linkSegs = new Set();
			for (const a of document.querySelectorAll('a[href]')) {
				for (const seg of (a.getAttribute('href') || '').split(/[/?#]/)) if (seg) linkSegs.add(seg.toLowerCase());
			}
			const instanceValued = (s) => {
				const vals = Array.from(s.options || []).map((o) => (o.value || '').trim().toLowerCase()).filter(Boolean);
				return vals.length >= 2 && vals.every((v) => /^\d+$/.test(v) || linkSegs.has(v));
			};
			const shellScope = [best, best.parentElement, best.parentElement && best.parentElement.parentElement].filter(Boolean);
			// A non-select switcher (a custom dropdown button) can't be recognised structurally, so it
			// still needs a naming hint — the one remaining keyword, only for that case.
			const ctxRe = /\b(workspace|organi[sz]ation|\borg\b|team|project|account|tenant|environment)\b/i;
			const contextSwitcher =
				shellScope.some((c) => Array.from(c.querySelectorAll('select')).some(instanceValued)) ||
				dests.some((e) => {
					const lab = (e.getAttribute('aria-label') || '') + ' ' + (e.textContent || '') + ' ' + (e.className || '');
					return ctxRe.test(lab) && (e.getAttribute('aria-haspopup') || /\b(switch|select)\b/i.test(lab) || e.querySelector('svg'));
				});
			// The switcher's option LABELS are the app's entity NAMES (org/workspace names). They DO ride
			// in the client→server audit payload (the server needs them to strip those exact names out of
			// prose before it sends anything to the LLM judge). They are NOT secrets and are not sent to
			// the judge — but be precise: they leave the browser to the uxlint server, they are not
			// browser-only. (They skip redactSecrets by design: masking them would defeat the name-strip.)
			let switcherOptions = [];
			for (const c of shellScope) {
				for (const s of c.querySelectorAll('select')) {
					if (!instanceValued(s)) continue;
					for (const o of s.options || []) { const t = (o.textContent || '').trim(); if (t) switcherOptions.push(t); }
				}
			}
			switcherOptions = [...new Set(switcherOptions)].slice(0, 30);
			// The switcher's own box, and whether a create affordance sits in its CLUSTER (the picker's
			// own row/parent, not the whole page). Where you switch between workspaces is where you
			// reach for a new one — Slack, Linear and Notion all put "New workspace" in or beside the
			// picker. Only the labels/geometry are used; option text stays server-side. Feeds
			// switcher-no-create.
			let switcherRect = null;
			let switcherHasCreate = false;
			try {
				let switcherEl = null;
				for (const c of shellScope) {
					const s = Array.from(c.querySelectorAll('select')).find(instanceValued);
					if (s) { switcherEl = s; break; }
				}
				if (!switcherEl) {
					switcherEl = dests.find((e) => {
						const lab = (e.getAttribute('aria-label') || '') + ' ' + (e.textContent || '') + ' ' + (e.className || '');
						return ctxRe.test(lab) && (e.getAttribute('aria-haspopup') || /\b(switch|select)\b/i.test(lab) || e.querySelector('svg'));
					}) || null;
				}
				if (switcherEl) {
					const r = switcherEl.getBoundingClientRect();
					if (r.width > 1 && r.height > 1) switcherRect = [r.x, r.y, r.width, r.height].map(Math.round);
					const CRE = /\b(new|add|create)\b/i;
					const cluster = (switcherEl.parentElement && switcherEl.parentElement.parentElement) || switcherEl.parentElement;
					for (const el of cluster ? cluster.querySelectorAll('a[href],button,[role=button],summary') : []) {
						if (el === switcherEl || el.contains(switcherEl)) continue;
						const lbl = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim(); // accessible name: aria-label wins over text (concatenating doubled a labelled "Create X" past the length cap)
						const href = el.getAttribute('href') || '';
						// A bare "+" counts: it's the affordance even when it's unlabelled (that's a
						// different lint's business, and this one must not double-report it).
						if ((CRE.test(lbl) && lbl.length <= 30) || /^[+＋]$/.test(lbl) || /\/(new|create)(\/|$)/.test(href)) {
							switcherHasCreate = true;
							break;
						}
					}
				}
			} catch (_) { /* ignore */ }
			// Utility items (account/settings/profile/preferences) sitting inline among the
			// primary destinations — these conventionally belong in a user menu, not here.
			const ACCT = /\b(settings|account|profile|preferences)\b/i;
			const acctEls = dests.filter(e => ACCT.test((e.getAttribute('aria-label') || '') + ' ' + (e.textContent || ''))
					// …but a WORKSPACE/org-scoped settings link (/orgs/…, /workspace/…, /team/…) is a legitimate primary
					// destination — GitHub, Vercel, Stripe and Railway all put workspace Settings in the main nav — NOT the
					// PERSONAL account-utility nav this lint targets (which belongs under the avatar / at the rail foot).
					&& !/\/(orgs?|workspaces?|teams?)(\/|$)/i.test(e.getAttribute('href') || ''));
			const accountItems = [...new Set(acctEls
				.map(e => ((e.getAttribute('aria-label') || '') + ' ' + (e.textContent || '')).replace(/\s+/g, ' ').trim())
				.filter(Boolean)
				.map(l => l.slice(0, 30)))].slice(0, 6);
			// Bottom-pinned in a SIDE nav is the OTHER accepted convention (settings at the
			// foot of a left rail — Slack/Linear/Notion). True only when every account item's
			// vertical centre sits in the lower 40% of a side nav.
			const accountItemRects = acctEls.slice(0, 6).map(e => { const r = e.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)]; });
			let accountItemsBottom = false;
			if (orientation === 'side' && acctEls.length) {
				const nr = best.getBoundingClientRect();
				const threshold = nr.top + nr.height * 0.6;
				accountItemsBottom = acctEls.every(e => {
					const r = e.getBoundingClientRect();
					return r.top + r.height / 2 >= threshold;
				});
			}
			// A user-menu affordance: the avatar/name control that opens account/settings. If
			// one exists, the app follows the convention and inline account items are excused.
			const AV = /avatar|profile|gravatar|user-?menu|account-?menu|\buser\b|\bme\b/i;
			let userMenu = false;
			try {
				const scope = Array.from(document.querySelectorAll('header, [role="banner"], nav, aside, [class*="topbar" i], [class*="navbar" i], [class*="appbar" i]'))
					.filter(n => { const r = n.getBoundingClientRect(); return r.width > 4 && r.height > 4 && n.offsetParent !== null; });
				outer: for (const s of scope) {
					for (const img of s.querySelectorAll('img')) {
						const r = img.getBoundingClientRect();
						if (r.width < 8 || r.width > 72 || img.offsetParent === null) continue;
						const cs = getComputedStyle(img);
						const rounded = cs.borderRadius.includes('%')
							? parseFloat(cs.borderRadius) >= 40
							: (parseFloat(cs.borderRadius) || 0) >= r.width * 0.35;
						const named = AV.test((img.getAttribute('alt') || '') + ' ' + (img.className || '') + ' ' + (img.getAttribute('src') || ''));
						if (rounded || named) { userMenu = true; break outer; }
					}
					for (const c of s.querySelectorAll('[aria-haspopup], button, [role="button"], summary')) {
						const r = c.getBoundingClientRect();
						if (r.width < 8 || c.offsetParent === null) continue;
						const name = (c.getAttribute('aria-label') || '') + ' ' + (c.textContent || '') + ' ' + (c.className || '');
						const pops = !!c.getAttribute('aria-haspopup');
						if ((pops || /\bmenu\b/i.test(name)) && AV.test(name)) { userMenu = true; break outer; }
						if (pops && c.querySelector('img')) { userMenu = true; break outer; }
						// Initials avatar: a small ~square control that opens a menu.
						if (pops && r.width >= 20 && r.width <= 64 && Math.abs(r.width - r.height) < r.width * 0.5) { userMenu = true; break outer; }
					}
				}
			} catch (_) { /* ignore */ }
			// Where user settings SHOULD live: an avatar/name in the top corner. If none, fall back to
			// the top-right of the header so the suggestion has somewhere to point (synthetic).
			let userTargetRect = null, userTargetSynthetic = false, userIdentityRect = null, userIsLink = false, userHasAvatar = false, userLabelGeneric = false;
			try {
				// The user identity to hang settings off: an email, an avatar, or an account/profile control
				// — searched INSIDE this nav (and any header), including the foot of a side rail.
				const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;
				const scopes = []; for (let anc = best, d = 0; anc && anc !== document.body && anc !== document.documentElement && d < 3; anc = anc.parentElement, d++) scopes.push(anc);
				const hdr = document.querySelector('header'); if (hdr) scopes.push(hdr);
				let idr = null, idEl = null, idScore = -1;
				for (const root of scopes) { for (const e of root.querySelectorAll('*')) {
					const cr = e.getBoundingClientRect();
					if (cr.width < 12 || cr.height < 10 || cr.width > 300 || e.offsetParent === null) continue;
					const inRegion = orientation === 'side' ? (cr.left + cr.width / 2 >= r.left - 8 && cr.left + cr.width / 2 <= r.right + 8) : (cr.top < r.bottom + 24);
					if (!inRegion) continue; // must sit in this nav's rail / header band, not elsewhere on the page
					const t = (e.textContent || '').replace(/\s+/g, ' ').trim(), kids = e.childElementCount;
					let score = -1;
					if (kids <= 3 && t.length <= 48 && EMAIL.test(t)) score = 3;
					else if (e.tagName === 'IMG' && Math.abs(cr.width - cr.height) < cr.width * 0.45) score = 2;
					else if (/avatar|user|account|profile/i.test((e.className || '') + ' ' + (e.getAttribute('aria-label') || ''))) score = 1;
					if (score < 0) continue;
					const pos = orientation === 'side' ? cr.top : cr.right;
					if (score > idScore || (score === idScore && idr && pos > (orientation === 'side' ? idr.top : idr.right))) { idScore = score; idr = cr; idEl = e; }
				} }
				if (idr) { userTargetRect = [Math.round(idr.left), Math.round(idr.top), Math.round(idr.width), Math.round(idr.height)]; userIdentityRect = userTargetRect; userIsLink = !!(idEl && idEl.closest('a[href],button,[role="link"],[role="button"]')); }
				else if (orientation === 'side') { const by = Math.min(r.bottom, vh) - 46; userTargetRect = [Math.round(r.left + 6), Math.round(by), Math.round(Math.min(r.width - 12, 220)), 40]; userTargetSynthetic = true; }
				else { userTargetRect = [Math.round(r.right - 146), Math.round(r.top + 6), 132, 34]; userTargetSynthetic = true; }
				// How the identity is PRESENTED, for identity-chrome. Two structural facts about the
				// control the identity sits in: does it carry an avatar, and does a generic settings
				// word ("Account", "Profile") lead over the identity itself? Both are conventions —
				// the identity IS the label, and an avatar is how people find it.
				if (idEl) {
					const ctl = idEl.closest('a[href],button,[role="link"],[role="button"]') || idEl;
					// Avatar: a small square-ish node that's an image, or a rounded chip (an initial).
					for (const e of ctl.querySelectorAll('img,span,div')) {
						const r2 = e.getBoundingClientRect();
						if (r2.width < 14 || r2.width > 56 || r2.height < 14) continue;
						if (Math.abs(r2.width - r2.height) > r2.width * 0.3) continue;
						if (e.tagName === 'IMG') { userHasAvatar = true; break; }
						const cs2 = getComputedStyle(e);
						const rad = cs2.borderRadius.includes('%')
							? parseFloat(cs2.borderRadius) >= 40
							: (parseFloat(cs2.borderRadius) || 0) >= r2.width * 0.35;
						const bg = cs2.backgroundColor || '';
						const filled = !!bg && bg !== 'transparent' && !/rgba\([^)]*,\s*0\s*\)/.test(bg);
						if (rad && (filled || (e.textContent || '').trim().length <= 2)) { userHasAvatar = true; break; }
					}
					// A generic settings word rendered at least as large as the identity leads it.
					const GEN = /^(my )?(account|profile|settings|account (&|and) billing|account settings)$/i;
					const idSize = parseFloat(getComputedStyle(idEl).fontSize) || 0;
					for (const e of ctl.querySelectorAll('*')) {
						if (e === idEl || e.contains(idEl) || e.childElementCount > 0) continue;
						const t = (e.textContent || '').replace(/\s+/g, ' ').trim();
						if (!GEN.test(t)) continue;
						if ((parseFloat(getComputedStyle(e).fontSize) || 0) >= idSize) { userLabelGeneric = true; break; }
					}
				}
			} catch (_) { /* ignore */ }
			primaryNav = { present: true, orientation, dests: dests.length, contextSwitcher, switcherOptions, switcherRect, switcherHasCreate, acquisition, accountItems, accountItemRects, accountItemsBottom, userMenu, hasSideNav, userTargetRect, userTargetSynthetic, userIdentityRect, userIsLink, userHasAvatar, userLabelGeneric };
		}
	} catch (_) { /* ignore */ }

	// Nav-landmark labelling (WCAG 1.3.1 / ARIA APG): when a page has ≥2 nav landmarks a
	// screen-reader user can only tell them apart if each carries a distinct accessible name.
	// count = visible nav landmarks; labelled = how many have a non-empty aria-label /
	// aria-labelledby; distinctLabelled = how many of those labels are unique.
	let navLandmarks = { count: 0, labelled: 0, distinctLabelled: 0 };
	try {
		const navs = Array.from(document.querySelectorAll('nav, [role="navigation"]')).filter(n => {
			const r = n.getBoundingClientRect();
			return r.width > 4 && r.height > 4 && n.offsetParent !== null;
		});
		const labels = navs.map(n => {
			let lab = (n.getAttribute('aria-label') || '').trim();
			if (!lab) {
				const lb = n.getAttribute('aria-labelledby');
				if (lb) lab = lb.split(/\s+/).map(id => (document.getElementById(id) || {}).textContent || '').join(' ').replace(/\s+/g, ' ').trim();
			}
			return lab.toLowerCase();
		}).filter(Boolean);
		// Rect of the first UNLABELLED nav (or the first nav) — anchors the report highlight.
		let rectNav = navs.find(n => {
			let lab = (n.getAttribute('aria-label') || '').trim() || (n.getAttribute('aria-labelledby') || '').trim();
			return !lab;
		}) || navs[0];
		let rect = null;
		if (rectNav) { const r = rectNav.getBoundingClientRect(); rect = [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)]; }
		// Every nav landmark's rect — so the report can box them all, not just the first.
		const rects = navs.map(n => { const r = n.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)]; });
		navLandmarks = { count: navs.length, labelled: labels.length, distinctLabelled: new Set(labels).size, rect, rects };
	} catch (_) { /* ignore */ }

	// In-page section nav (an "on this page" / table-of-contents list of same-page anchor
	// links). On mobile a static one at the top scrolls out of view; sticky or collapsible is fine.
	let inPageNav = { present: false, sticky: false, collapsible: false, rect: null };
	try {
		// Semantic navs are considered BEFORE bare <div>s (not merged in document order): a sticky
		// "On this page" <nav> is very often wrapped in a plain container div, and that outer div —
		// whose grandchildren are the nav's own anchors — would otherwise match first and report the
		// wrapper's (non-sticky) position instead of the real, sticky nav's. Prefer the real one.
		for (const el of [...document.querySelectorAll('nav, [role="navigation"], aside, ol, ul'), ...document.querySelectorAll('div')]) {
			// Semantic containers count anchors anywhere inside; a bare <div> only qualifies as a nav
			// when its OWN row of links is the anchor set (a chip/jump bar) — not any div that merely
			// contains scattered same-page links. Keeps it tight enough to avoid false positives.
			const semantic = el.matches('nav, [role="navigation"], aside, ol, ul');
			const linkSel = semantic ? 'a[href]' : ':scope > a[href], :scope > * > a[href]';
			const anchorSel = semantic ? 'a[href^="#"]' : ':scope > a[href^="#"], :scope > * > a[href^="#"]';
			const anchors = Array.from(el.querySelectorAll(anchorSel)).filter(a => { const r = a.getBoundingClientRect(); return r.width > 2 && r.height > 2 && a.offsetParent !== null; });
			if (anchors.length < 3) continue;
			const allLinks = el.querySelectorAll(linkSel).length;
			if (anchors.length < allLinks * 0.6) continue; // predominantly in-page anchors
			const r = el.getBoundingClientRect();
			if (r.width < 4 || r.height < 4 || el.offsetParent === null) continue;
			let sticky = false;
			for (let p = el; p && p !== document.body; p = p.parentElement) { const pos = getComputedStyle(p).position; if (pos === 'sticky' || pos === 'fixed') { sticky = true; break; } }
			const collapsible = !!el.closest('details') || !!el.querySelector('[aria-expanded],summary') || !!(el.previousElementSibling && el.previousElementSibling.getAttribute && el.previousElementSibling.getAttribute('aria-expanded') !== null);
			inPageNav = { present: true, sticky, collapsible, rect: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)] };
			break;
		}
	} catch (_) { /* ignore */ }

	// Fallback: a COLLAPSED in-page nav — an "on this page" list folded inside a closed <details> /
	// disclosure (the standard mobile pattern). Its anchors are display:none while shut, so the
	// visible-anchor scan above misses them and the page looks like it has no TOC. Detect the DISCLOSURE
	// itself (its summary IS on-screen) when it holds a predominantly-#anchor link set, so a jumpable
	// page isn't mistaken for a nav-less one on mobile. `collapsible: true` — it's fine, just folded.
	if (!inPageNav.present) {
		try {
			for (const d of document.querySelectorAll('details')) {
				if (d.offsetParent === null) continue; // the disclosure itself must be rendered
				const anchors = d.querySelectorAll('a[href^="#"]');
				if (anchors.length < 3) continue;
				const allLinks = d.querySelectorAll('a[href]').length;
				if (anchors.length < allLinks * 0.6) continue; // predominantly in-page anchors
				const r = d.getBoundingClientRect();
				if (r.width < 4 || r.height < 4) continue;
				inPageNav = { present: true, sticky: false, collapsible: true, rect: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)] };
				break;
			}
		} catch (_) { /* ignore */ }
	}

	// Breadcrumb presence (NN/g deep-hierarchy best practice; WCAG 2.4.8 Location). A
	// breadcrumb is a nav labelled "breadcrumb", an element whose class/id says so, or an
	// ordered list of ≥2 links joined by a separator (/ › » →).
	// Cross-page theme + layout fingerprint: the tokens that should stay consistent site-wide —
	// the base font, the page background, the body text colour, and the content-column width.
	// The cross-page theme-consistency / layout-consistency lints compare these across routes.
	let pageTheme = { font: '', bg: null, text: null, contentW: 0 };
	try {
		const firstFont = (f) => (f || '').split(',')[0].replace(/["']/g, '').trim().toLowerCase();
		const bcs = getComputedStyle(document.body);
		const rgb = (c) => (c ? [Math.round(c.r), Math.round(c.g), Math.round(c.b)] : null);
		const mainEl = document.querySelector('main, [role="main"]');
		// Content-column width = the TYPICAL paragraph width (median), not the <main> box. A page
		// can have a full-bleed <main> with its text centred in a narrow column (the common
		// marketing pattern) — measuring the box would call that "full width" when the reading
		// column is actually 700px. The median paragraph width tracks the real content column and
		// ignores stray full-width footer/section text. 0 when there aren't enough paragraphs.
		const contentW = (() => {
			const scope = mainEl || document.body;
			const ws = Array.from(scope.querySelectorAll('p'))
				.filter((e) => e.offsetParent !== null)
				.map((e) => e.getBoundingClientRect().width)
				.filter((w) => w > 80)
				.sort((a, b) => a - b);
			return ws.length >= 2 ? Math.round(ws[Math.floor(ws.length / 2)]) : 0;
		})();
		// Container width = the max-width the content column is CAPPED at — the widest block inside
		// <main> that is wide (a layout container, not a stray element) yet still leaves real side
		// margins (not full-bleed to the viewport). This is what the eye reads as "the page width":
		// two pages that cap their content at different max-widths (e.g. max-w-5xl vs max-w-4xl)
		// have visibly different margins even when their paragraph column is the same. 0 when the
		// page is genuinely fluid (no capped container), so it's excluded from the cross-page check.
		const containerW = (() => {
			const vw = window.innerWidth || document.documentElement.clientWidth || 0;
			if (vw <= 0) return 0;
			// A CENTERED content column: wide, leaving real margins on BOTH sides that are roughly
			// symmetric (the `max-w-* mx-auto` pattern). This is what should stay one width across a
			// site. A full-bleed view, or a left-aligned column inside an app shell (margin only on
			// one side), is NOT centered — it can use the whole screen, so it reports 0 and is exempt
			// from the cross-page check. Prefer <main>'s own box; fall back to the widest centered
			// block when <main> itself is full-bleed but wraps a centered container.
			const centered = (r) => {
				const left = r.left, right = vw - r.right;
				return (
					r.width >= vw * 0.4 &&
					r.width <= vw * 0.95 &&
					left > 8 &&
					right > 8 &&
					Math.abs(left - right) <= vw * 0.06
				);
			};
			if (mainEl) {
				const mr = mainEl.getBoundingClientRect();
				if (centered(mr)) return Math.round(mr.width);
				// <main> isn't a centered column. If it's a left-aligned APP-SHELL column — a large
				// margin on ONE side only (a sidebar), not full-bleed — it legitimately uses the width
				// beside the shell and is NOT a centered content column that must match a site-wide
				// max-width: exempt it (0). Otherwise a stray centered descendant (e.g. one grid layout
				// on /sites) stands in for "the page width" and the page reads as a phantom outlier.
				// Only a genuinely FULL-BLEED <main> (small margins on BOTH sides) wraps a centered
				// content container worth measuring, so fall through to the descendant scan just then.
				const fullBleed = mr.left <= vw * 0.02 && vw - mr.right <= vw * 0.02;
				if (!fullBleed) return 0;
			}
			let best = 0;
			for (const e of (mainEl || document.body).querySelectorAll('*')) {
				if (e.offsetParent === null) continue;
				const r = e.getBoundingClientRect();
				if (centered(r) && r.width > best) best = r.width;
			}
			return Math.round(best);
		})();
		pageTheme = { font: firstFont(bcs.fontFamily), bg: rgb(pageBg), text: rgb(parseColor(bcs.color)), contentW, containerW };
	} catch (_) { /* ignore */ }

	// Frame vs content alignment: the horizontal extent of the centred CONTENT column vs the
	// header and footer content. When the content sits in a centred column but the header/footer
	// run edge-to-edge, the logo/nav don't line up with the content below (ragged left/right edges).
	let frame = { content: null, header: null, footer: null };
	try {
		const vis = (el) => { const r = el.getBoundingClientRect(); return r.width > 4 && r.height > 4 && el.offsetParent !== null; };
		const extent = (els) => { let l = Infinity, r = -Infinity; for (const e of els) { const b = e.getBoundingClientRect(); if (b.left < l) l = b.left; if (b.right > r) r = b.right; } return r > l ? [Math.round(l), Math.round(r)] : null; };
		// The content COLUMN: the extent of the main content, EXCLUDING full-bleed outliers (a logo
		// strip, a coloured band that spans edge-to-edge) so a single full-width section doesn't
		// report the column as full-width when the real reading column is capped and centred.
		const scope = document.querySelector('main, [role="main"]') || document.body;
		const contentEls = Array.from(scope.querySelectorAll('h1,h2,h3,p,ul,ol,figure')).filter((e) => {
			if (!vis(e) || e.closest('header,footer,nav,[role="banner"],[role="contentinfo"]')) return false;
			return e.getBoundingClientRect().width < window.innerWidth * 0.9; // drop full-bleed elements
		});
		if (contentEls.length >= 3) frame.content = extent(contentEls);
		// The header/footer's own leaf content (logo, nav items) — not the full-bleed bar itself.
		const frameExtent = (sel) => { const el = document.querySelector(sel); if (!el || !vis(el)) return null; const leaves = Array.from(el.querySelectorAll('a,button,img,svg,span,li')).filter(vis); return extent(leaves.length ? leaves : Array.from(el.children).filter(vis)); };
		frame.header = frameExtent('header, [role="banner"]');
		frame.footer = frameExtent('footer, [role="contentinfo"]');
	} catch (_) { /* ignore */ }

	// Embedded frames — box, visibility, and the embed's HOST. Nothing else in the snapshot can see
	// an <iframe>: they aren't captured as elements, so "is there a third-party frame here, and does
	// it stick out past the viewport?" is unanswerable today. It is a real defect — a hidden
	// fraud-detection frame laid out wider than the window adds a horizontal scrollbar to every page
	// it loads on, and because it paints nothing the cause is invisible to the eye.
	//
	// The HOST ONLY, deliberately — never the full src. An embed URL routinely carries session ids,
	// one-time tokens and customer identifiers in its query string, and this JSON is POSTed to our
	// server. The host is the whole question ("ours or someone else's?"); the query string is
	// somebody's credential and has no business leaving the page.
	//
	// Only the ELEMENT is read — attributes and box, never `contentDocument` — so a cross-origin
	// frame is exactly as readable as a same-origin one and nothing here can trip a security error.
	const iframes = [];
	try {
		const pageHost = location.hostname;
		// Same site = the same registrable domain (the last two labels) — the SAME rule the crawl uses
		// to decide what is off-site (`same_site` in worker.rs), so the two can't disagree about whose
		// frame this is: `app.acme.com` embedding `assets.acme.com` is our own embed, not a stranger's.
		// An IP or a bare hostname (localhost) matches exactly. It over-merges a multi-tenant eTLD
		// (`a.co.uk` vs `b.co.uk`), which can only ever MISS a third party — the safe direction for a
		// signal a lint accuses someone with. Decided here because `location` is the authority on what
		// the page's origin actually is.
		const regDomain = (h) => {
			if (!h.includes('.') || h.includes(':') || /^[\d.]+$/.test(h)) return h; // bare host / IPv6 / IPv4
			return h.split('.').slice(-2).join('.');
		};
		const pageReg = regDomain(pageHost);
		for (const f of document.querySelectorAll('iframe')) {
			if (iframes.length >= 60) break; // ad-stuffed pages; the trim below keeps the payload small
			let host = '';
			const src = f.getAttribute('src') || '';
			// Resolve RELATIVE srcs against the page, or a first-party `/embed/x` reads as host-less
			// and escapes first-party detection. srcdoc / about:blank / javascript: / data: frames have
			// no host at all — inline content, first-party by construction — and stay host-less.
			if (src && !/^(about:|javascript:|data:|blob:)/i.test(src)) {
				try { host = new URL(src, location.href).hostname; } catch (_) { /* unparseable src */ }
			}
			const cs = getComputedStyle(f);
			const r = f.getBoundingClientRect();
			// "Visually hidden" = paints nothing, by any of the usual techniques. A 1px-thin frame
			// counts: it is invisible to the eye yet still occupies (and can overflow) layout, and that
			// exact combination — no pixels, full width — is the defect worth reporting.
			const hidden = cs.display === 'none' || cs.visibility !== 'visible' ||
				(parseFloat(cs.opacity) || 0) < 0.05 || f.hasAttribute('hidden') ||
				f.getAttribute('aria-hidden') === 'true' || r.width <= 2 || r.height <= 2;
			const o = { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) };
			if (host) o.host = host;
			if (host && regDomain(host) !== pageReg) o.tp = true;
			if (hidden) o.hidden = true;
			iframes.push(o);
		}
		// Keep the payload bounded. When a page embeds more frames than we'll send, keep the WIDEST —
		// width is the whole question here, so trimming by document order would be the one way to drop
		// the offender and keep eleven ad slots.
		if (iframes.length > 12) { iframes.sort((a, b) => b.w - a.w); iframes.length = 12; }
	} catch (_) { /* ignore */ }

	let breadcrumb = false;
	try {
		if (document.querySelector('nav[aria-label*="breadcrumb" i], [class*="breadcrumb" i], [id*="breadcrumb" i], [aria-label*="breadcrumb" i]')) {
			breadcrumb = true;
		} else {
			for (const ol of document.querySelectorAll('ol, ul, nav')) {
				const r = ol.getBoundingClientRect();
				if (r.height > 4 && ol.querySelectorAll('a[href]').length >= 2 && /[/›»→›»]/.test(ol.textContent || '')) { breadcrumb = true; break; }
			}
		}
	} catch (_) { /* ignore */ }

	// Vague link text (WCAG 2.4.4 / 2.4.9, NN/g): links whose ENTIRE accessible name is a
	// generic filler phrase carry no scent — out of context they're meaningless. Only flag
	// exact whole-name matches (an aria-label giving a real name rescues the link).
	const VAGUE = new Set(['click here', 'click', 'here', 'read more', 'learn more', 'more', 'read', 'this', 'link', 'details', 'view', 'view more', 'continue', 'go', 'see more', 'find out more']);
	let vagueLinks = [], vagueLinkRects = [];
	// New tab without warning (WCAG 3.2.5 / G201, NN/g): target=_blank that gives no cue
	// (no "new tab/window" text, no external-link icon) yanks the user out unexpectedly.
	let newTabUnwarned = [], newTabRects = [];
	try {
		const links = Array.from(document.querySelectorAll('a[href], [role="link"]')).filter(a => {
			const r = a.getBoundingClientRect();
			return r.width > 4 && r.height > 4 && a.offsetParent !== null;
		});
		for (const a of links) {
			const aria = (a.getAttribute('aria-label') || '').trim();
			const name = (aria || a.getAttribute('title') || a.textContent || '').replace(/\s+/g, ' ').trim();
			const low = name.toLowerCase().replace(/[.!?→›»↗⧉↗⧉]+$/g, '').trim();
			if (name && VAGUE.has(low) && vagueLinks.length < 6) { vagueLinks.push(name.slice(0, 40)); var vr=a.getBoundingClientRect(); vagueLinkRects.push([Math.round(vr.left),Math.round(vr.top),Math.round(vr.width),Math.round(vr.height)]); }
			if ((a.getAttribute('target') || '') === '_blank') {
				const warned = /\bnew (tab|window)\b/i.test(name) ||
					a.querySelector('svg, img, [class*="external" i], [class*="new-tab" i]') !== null ||
					/[↗⧉↗⧉⬈❐]/.test(a.textContent || '');
				if (!warned && newTabUnwarned.length < 6) { newTabUnwarned.push((name || a.getAttribute('href') || '').slice(0, 40)); var nr=a.getBoundingClientRect(); newTabRects.push([Math.round(nr.left),Math.round(nr.top),Math.round(nr.width),Math.round(nr.height)]); }
			}
		}
	} catch (_) { /* ignore */ }

	// Does the site theme its scrollbars? A dark page left with the browser-default (light)
	// scrollbar looks unfinished. True if `color-scheme` darkens the native scrollbar, or CSS
	// styles it (`::-webkit-scrollbar`, `scrollbar-color`, `scrollbar-width`).
	const scrollbarThemed = (() => {
		try {
			for (const el of [document.documentElement, document.body]) {
				const cs = getComputedStyle(el);
				if (/dark/.test(cs.colorScheme || '')) return true;
				if ((cs.scrollbarColor || 'auto') !== 'auto') return true;
				if (cs.scrollbarWidth && cs.scrollbarWidth !== 'auto') return true;
			}
			for (const ss of document.styleSheets) {
				let rules;
				try { rules = ss.cssRules; } catch (_) { continue; }
				if (!rules) continue;
				for (const r of rules) {
					if ((r.selectorText || '').includes('-webkit-scrollbar')) return true;
					if (/scrollbar-color|scrollbar-width/i.test(r.cssText || '')) return true;
				}
			}
		} catch (_) { /* cross-origin sheet or unsupported prop */ }
		return false;
	})();

	// Does the page declare a light/dark THEMING story? Only then is a hardcoded-colour diagram a real
	// bug (see svg-untokenized) — on a light-only site baked-in SVG colours are fine. Signals, strongest
	// first: a `color-scheme` naming dark, a `prefers-color-scheme` media rule in a stylesheet, a
	// <meta name=color-scheme> with dark, a `data-theme`/`data-*-theme` switch attribute, or Tailwind's
	// `.dark` class on <html>/<body>.
	const themeable = (() => {
		try {
			const de = document.documentElement, bd = document.body;
			for (const n of [de, bd]) {
				if (!n) continue;
				if (/dark/.test(getComputedStyle(n).colorScheme || '')) return true;
				for (const a of n.attributes) {
					if (/^data-(theme|color-scheme|mode|bs-theme)$/i.test(a.name) && /dark|light/i.test(a.value)) return true;
				}
				if (/(^|\s)dark(\s|$)/.test(n.className || '')) return true;
			}
			const meta = document.querySelector('meta[name="color-scheme"]');
			if (meta && /dark/i.test(meta.getAttribute('content') || '')) return true;
			for (const ss of document.styleSheets) {
				let rules;
				try { rules = ss.cssRules; } catch (_) { continue; } // cross-origin sheet
				if (!rules) continue;
				for (const r of rules) {
					if (r.type === CSSRule.MEDIA_RULE && /prefers-color-scheme\s*:\s*dark/i.test(r.conditionText || r.media?.mediaText || '')) return true;
				}
			}
		} catch (_) { /* unsupported — treat as not themeable */ }
		return false;
	})();

	// Is the vertical scrollbar's GUTTER reserved regardless of content height? If not, a page that
	// overflows shows a scrollbar and one that fits doesn't — and the ~15px gutter appearing /
	// disappearing shifts centred content sideways as you move between same-type pages. Reserved by
	// `scrollbar-gutter: stable` on the root, or a permanent scrollbar (`overflow-y: scroll`), or
	// overlay scrollbars that take no space (scrollbar-width: none / thin on some platforms).
	const gutterStable = (() => {
		try {
			const de = document.documentElement, dcs = getComputedStyle(de), bcs = getComputedStyle(document.body);
			if (/stable/.test(dcs.scrollbarGutter || '')) return true;
			if (dcs.overflowY === 'scroll' || bcs.overflowY === 'scroll') return true;
			if (dcs.scrollbarWidth === 'none' || bcs.scrollbarWidth === 'none') return true; // no gutter to shift
		} catch (_) { /* unsupported prop */ }
		return false;
	})();

	return {
		scrollbarThemed,
		gutterStable,
		docTitle: document.title,
		authChrome,
		primaryNav,
		navLandmarks,
		inPageNav,
		pageTheme,
		frame,
		iframes,
		breadcrumb,
		vagueLinks,
		vagueLinkRects,
		newTabUnwarned,
		newTabRects,
		htmlLang,
		copyrightYear,
		pageYear,
		genericSubmitLabels,
		formColumns,
		linkColorOnly,
		linkColorOnlyRect,
		linkColorOnlyRects,
		dataCramped,
		wastedSideFrac,
		framework,
		widgetLib,
		css,
		js,
		metaDescription,
		ogTags,
		ogImage,
		iconLink,
		mobile,
		dateMarkers,
		codeBlocks,
		codeBlocksNoCopy,
		authAffordances,
		searchable,
		collectionMax,
		collectionRect,
		listHeight,
		listItems,
		listRowLinkCoverage,
		headingCount,
		headingPanelRatio,
		entityIndex,
		entityIndexRoot,
		hasCreate,
		emptyState,
		svgOffCenterLabels,
		svgUnbalanced,
		svgUntokenized,
		themeable,
		emptyStranded,
		emptyStrandedRect,
		secretNoCopy,
		collectionKind,
		collectionSel,
		collectionDrillable,
		paginated,
		aiGenControls,
		manualEditControls,
		i18nRows,
		prose: prose.slice(0, 6000),
		sections,
		junkBuckets,
		anchorIds,
		scrollOffsets,
		asides: asides.slice(0, 1500),
		codeText: codeText.slice(0, 2500),
		spinnerCount: document.querySelectorAll('.animate-spin').length,
		vw,
		vh,
		scrollW: document.documentElement.scrollWidth,
		scrollH: document.documentElement.scrollHeight,
		tokens,
		count: els.length,
		elements: els,
		palette
	};
}

return JSON.stringify(collectSnapshot());
})()