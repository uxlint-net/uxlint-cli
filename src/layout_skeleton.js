// LAYOUT SKELETON extractor — runs in the audited page (injected via `evaluate`) and returns a
// compact, HIGH-LEVEL text map of the page's semantic layout: landmarks and regions, collections
// summarised (nav/list/table/form by count/shape), and — the key move — runs of similar blocks
// collapsed by GEOMETRY into "N× columns"/"N× stacked" with the pattern shown once. No HTML/CSS/JS
// noise, just roles + final positions. This is the representation the archetype lint hands to the
// text judge (DeepSeek), which reasons over layout far better than a 7B VLM can perceive it.
//
// INTEGRATION TODO: `include_str!` this into the snapshot capture and post the result as
// snapshot.layout_skeleton; the server-side archetype lint then proposes the fit layout from
// page-type + this skeleton and flags a CONFIRMED structural mismatch (e.g. a pricing page whose
// tiers are stacked, not columns). Grouping is geometry-based, so the mismatch signal is grounded.
// Semantic layout skeleton (HIGH-LEVEL): walk the rendered DOM and emit a compact map of the page's
// LAYOUT, not its every node. Landmarks and regions are kept; collections (nav, lists, tables, forms)
// are summarised by count/shape rather than enumerated; and — the key move — runs of structurally
// similar siblings (cards, tiers, rows) collapse to "N× {pattern} [arrangement]" instead of being
// spelled out. This is the page stripped to the structure an LLM needs to reason about layout.
(() => { try {
  const cs = (el) => getComputedStyle(el);
  const hidden = (el) => { const s = cs(el); return s.display === 'none' || s.visibility === 'hidden' || +s.opacity < 0.05; };
  const big = (el) => { const r = el.getBoundingClientRect(); return r.width >= 2 && r.height >= 2; };
  const R = (el) => { const r = el.getBoundingClientRect(); return [r.x, r.y, r.width, r.height].map(Math.round); };
  // Best-effort redaction of API-key / token / secret-shaped values before they enter the skeleton —
  // which is stored AND sent to the model. Pattern-based (not a guarantee); see the collector note.
  const SECRET_RES = [
    /\b(?:sk|rk|pk)[-_](?:live|test|prod|proj)?[-_]?[A-Za-z0-9]{16,}\b/g,
    /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\bAIza[0-9A-Za-z_-]{35}\b/g,
    /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g,
    /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/gi,
  ];
  const SECRET_LAB = /\b(api[\s_-]?key|secret|token|password|passwd|access[\s_-]?key|client[\s_-]?secret)\b(["'\s:=]{1,4})([A-Za-z0-9._~+/-]{12,}=*)/gi;
  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  const redact = (t) => { let o = t || ''; for (const re of SECRET_RES) o = o.replace(re, '[redacted]'); return o.replace(SECRET_LAB, (m, l, s) => l + s + '[redacted]').replace(EMAIL_RE, '[email]'); };
  const clip = (t, n = 42) => { t = redact((t || '').replace(/\s+/g, ' ').trim()); return t.length > n ? t.slice(0, n) + '…' : t; };

  const LANDMARK = { HEADER: 'header', NAV: 'nav', MAIN: 'main', ASIDE: 'aside', FOOTER: 'footer', FORM: 'form', ARTICLE: 'article', SECTION: 'section', DIALOG: 'dialog' };
  const role = (el) => {
    const t = el.tagName, r = (el.getAttribute('role') || '').toLowerCase();
    if (el.matches('input,textarea,select')) return 'field:' + (el.getAttribute('type') || t.toLowerCase());
    if (el.matches('button') || r === 'button') return 'button';
    if (el.matches('a[href]') || r === 'link') return 'link';
    if (/^H[1-6]$/.test(t)) return t.toLowerCase();
    if (el.matches('img,svg') || r === 'img') return 'img';
    if (el.matches('table') || r === 'table' || r === 'grid') return 'table';
    if (r === 'tree') return 'tree';
    if (r === 'tablist') return 'tablist';
    if (el.matches('details')) return 'disclosure'; // accordion item (summary + collapsible body)
    if (el.matches('ul,ol') || r === 'list' || r === 'menu') return 'list';
    // A <nav> that just WRAPS a tree/menu is a layout wrapper, not a link nav — descend so the inner
    // component (which carries the real structure) surfaces instead of "nav (0 links)".
    if (el.matches('nav') || r === 'navigation') return el.querySelector('[role=tree],[role=menu]') ? null : 'nav';
    if (r === 'dialog' || r === 'alertdialog') return 'dialog'; // role=dialog on any element, not just <dialog>
    if (LANDMARK[t]) return LANDMARK[t].toLowerCase();
    const own = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent).join(' ').trim();
    if (el.matches('p,h1,h2,h3,h4,h5,h6,li,label,td,th,figcaption,blockquote,pre') && own) return 'text';
    return null;
  };
  // Collections we summarise (never enumerate their items) and containers we descend into.
  const COLLECTION = /^(nav|list|table|tree|tablist|form)$/;
  const REGION = /^(header|main|aside|footer|section|article|dialog)$/;

  const label = (el, rl) => {
    if (rl.startsWith('field')) {
      const id = el.id, lab = id && document.querySelector(`label[for="${CSS.escape(id)}"]`);
      return clip((lab && lab.textContent) || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '');
    }
    if (rl === 'disclosure') { const sm = el.querySelector('summary'); return clip((sm || el).textContent); }
    if (rl === 'text' || rl.match(/^h[1-6]$/)) return clip(el.textContent);
    return clip(el.getAttribute('aria-label') || el.textContent || el.getAttribute('alt') || '');
  };
  const stateTag = (el) => {
    const s = [];
    if (el.tagName === 'DETAILS') s.push(el.open ? 'open' : 'closed');
    if (el.getAttribute('aria-selected') === 'true' || el.getAttribute('aria-current')) s.push('selected');
    if (el.getAttribute('aria-expanded')) s.push(el.getAttribute('aria-expanded') === 'true' ? 'expanded' : 'collapsed');
    if (el.disabled) s.push('disabled');
    return s.length ? ' {' + s.join(',') + '}' : '';
  };

  // Flatten to the page's semantic ATOMS: role-bearing elements (headings, text, controls,
  // collections, nested regions), descending THROUGH every styling/layout wrapper and card. Grouping
  // is then done by GEOMETRY (below), not by guessing which div is a card — that's the robust engine.
  const kidsOf = (el) => {
    const out = [];
    const rec = (n) => { for (const c of n.children) { if (hidden(c)) continue; if (role(c) && big(c)) out.push(c); else rec(c); } };
    rec(el);
    return out;
  };
  // ── geometry grouping helpers ──
  const seqKey = (items) => items.map((e) => role(e)).join(','); // role sequence, for matching groups
  const seqDesc = (items) => items.map((e) => { const r = role(e); return COLLECTION.test(r) ? `${r}(${e.querySelectorAll('li,[role=listitem],[role=treeitem]').length || ''})` : r; }).join(' · ');
  const groupLabel = (items) => { const h = items.find((e) => /^h[1-6]$/.test(role(e))); return h ? clip(h.textContent, 22) : ''; };
  // Cluster atoms into COLUMNS by shared left edge (each column's items ordered top→bottom).
  const clusterByX = (atoms) => {
    const cols = [];
    for (const e of [...atoms].sort((a, b) => R(a)[0] - R(b)[0])) {
      const x = R(e)[0];
      const c = cols.find((c) => Math.abs(c.x - x) <= 40);
      if (c) c.items.push(e); else cols.push({ x, items: [e] });
    }
    for (const c of cols) c.items.sort((a, b) => R(a)[1] - R(b)[1]);
    return cols;
  };
  // Split a vertical run into chunks that each START with a heading (a card's own title).
  const chunkByHeading = (items) => {
    const chunks = []; let cur = null;
    for (const e of [...items].sort((a, b) => R(a)[1] - R(b)[1])) {
      if (/^h[1-6]$/.test(role(e)) || !cur) { cur = [e]; chunks.push(cur); } else cur.push(e);
    }
    return chunks;
  };

  let out = [], count = 0;
  const P = (d, s) => out.push('  '.repeat(d) + s);
  const summarise = (el, rl) => { // one-line for a collection (no enumeration)
    const [x, y, w, h] = R(el);
    const at = ` [${x},${y} ${w}×${h}]`;
    if (rl === 'nav') {
      if (/breadcrumb/i.test(el.getAttribute('aria-label') || '')) {
        // One level per <li> (or per link when there are no list items); drop pure separators.
        const src = el.querySelector('li') ? [...el.querySelectorAll('li')] : [...el.querySelectorAll('a')];
        const trail = src.map((e) => clip(e.textContent, 16)).filter((t) => t && !/^[\s/>›»·|–-]+$/.test(t));
        return `breadcrumb (${trail.join(' › ')})${at}`;
      }
      const links = el.querySelectorAll('a[href],button').length;
      // A narrow, tall column of links alongside content is a SIDE NAV / table of contents — name it
      // so, or the reader can't tell a docs sidebar from a top nav (and false-flags "needs a TOC").
      const sidebar = h > w * 1.5 && w < 320;
      return `${sidebar ? 'sidebar-nav (table of contents)' : 'nav'} (${links} links)${at}`;
    }
    if (rl === 'tablist') { const tabs = [...el.querySelectorAll('[role=tab]')]; const sel = tabs.findIndex((t) => t.getAttribute('aria-selected') === 'true'); return `tabs (${tabs.length}: ${tabs.map((t) => clip(t.textContent, 14)).join(', ')})${sel >= 0 ? ` — active: ${clip(tabs[sel].textContent, 14)}` : ''}${at}`; }
    if (rl === 'list' || rl === 'tree') return `${rl} (${el.querySelectorAll('li,[role=listitem],[role=treeitem]').length} items)${at}`;
    if (rl === 'table') { const r = el.querySelectorAll('tr').length, c = (el.querySelector('tr') || { children: [] }).children.length; return `table (${r}×${c})${at}`; }
    if (rl === 'form') { const fs = [...el.querySelectorAll('input,textarea,select')].filter((e) => !hidden(e)); return `form (${fs.length} fields: ${fs.map((f) => f.getAttribute('type') || f.tagName.toLowerCase()).join(', ')})${at}`; }
    return rl + at;
  };

  const walk = (el, depth) => {
    if (count > 250 || hidden(el) || !big(el)) return;
    const rl = role(el);
    if (rl && COLLECTION.test(rl)) { count++; P(depth, summarise(el, rl)); return; } // summarise, don't recurse
    if (rl && !REGION.test(rl)) { // a leaf control / heading / text / img
      count++; const [x, y, w, h] = R(el);
      P(depth, `${rl}${(() => { const l = label(el, rl); return l ? ` "${l}"` : ''; })()}${stateTag(el)} [${x},${y} ${w}×${h}]`);
      return;
    }
    if (rl) { count++; const [x, y, w, h] = R(el); const al = clip(el.getAttribute('aria-label') || '', 30); P(depth, `${rl}${al ? ` "${al}"` : ''} [${x},${y} ${w}×${h}]`); } // region
    const cd = rl ? depth + 1 : depth;
    processChildren(el, cd);
  };

  // Process a region: nested regions recurse; runs of content atoms are grouped by GEOMETRY —
  // repeated columns (a comparison band) or a repeated vertical pattern (stacked cards) collapse to
  // one "N× …" line; anything left is listed.
  // Group ALL children by geometry — including small repeated regions (a grid of <article>/<section>
  // cards), which should collapse to a band, not be listed one by one. A lone/large region isn't part
  // of any band, so it falls through to walk() and recurses as structure.
  const processChildren = (el, depth) => groupAtoms(kidsOf(el), depth);
  const childSeq = (el) => { const d = seqDesc(kidsOf(el)); return d || role(el); };
  const groupAtoms = (atoms, depth) => {
    if (count > 250) return;
    if (atoms.length === 1) { walk(atoms[0], depth); return; }
    // 0) a run of ≥3 same-kind card blocks (article/section cards, media tiles) — collapse by
    // geometry into a grid or stack. These are repeated REGIONS whose own title sits inside them, so
    // the heading-chunk and column branches below miss them.
    const CARD = /^(article|section|img|table)$/;
    const byRole = {};
    for (const a of atoms) if (CARD.test(role(a))) (byRole[role(a)] = byRole[role(a)] || []).push(a);
    const dom = Object.values(byRole).sort((a, b) => b.length - a.length)[0] || [];
    if (dom.length >= 3) {
      const nc = clusterByX(dom).filter((c) => c.items.length >= 1).length;
      const shape = nc >= 2 ? `a ${nc}-column grid` : 'stacked vertically';
      P(depth, `${dom.length}× cards ${shape} — each { ${childSeq(dom[0])} }`);
      count++;
      const inCard = new Set(dom);
      for (const a of atoms) if (!inCard.has(a)) walk(a, depth);
      return;
    }
    // 1) repeated COLUMNS: cluster only the NARROW atoms (full-width headings/intros aren't columns
    // and would wreck the y-band check), then require ≥2 x-clusters of ≥2 items sharing a y-band and
    // near-equal counts. Real cards vary a little (a badge, an extra line) so match on shape, not an
    // exact sequence. Full-width atoms are walked in place around the collapsed band.
    const W = Math.max(...atoms.map((a) => R(a)[2]));
    const narrow = atoms.filter((a) => R(a)[2] < W * 0.6);
    const cols = clusterByX(narrow).filter((c) => c.items.length >= 2);
    if (cols.length >= 2) {
      const tops = cols.map((c) => R(c.items[0])[1]);
      const counts = cols.map((c) => c.items.length);
      const yBand = Math.max(...tops) - Math.min(...tops) < 60;
      const evenCounts = Math.max(...counts) - Math.min(...counts) <= 2;
      if (yBand && evenCounts) {
        const rep = cols.reduce((a, b) => (b.items.length > a.items.length ? b : a));
        const labels = cols.map((c) => groupLabel(c.items)).filter(Boolean);
        const line = `${cols.length}× columns side-by-side — each ≈ { ${seqDesc(rep.items)} }${labels.length ? ` — ${labels.join(', ')}` : ''}`;
        const inCol = new Set(cols.flatMap((c) => c.items));
        let emitted = false;
        for (const a of atoms) {
          if (inCol.has(a)) { if (!emitted) { P(depth, line); count++; emitted = true; } } else walk(a, depth);
        }
        return;
      }
    }
    // 2) repeated STACK: heading-delimited chunks, ≥2 consecutive with the same role sequence.
    const chunks = chunkByHeading(atoms);
    let i = 0;
    while (i < chunks.length) {
      const k = seqKey(chunks[i]); let j = i + 1;
      while (j < chunks.length && seqKey(chunks[j]) === k) j++;
      if (j - i >= 2) {
        const labels = chunks.slice(i, j).map(groupLabel).filter(Boolean);
        P(depth, `${j - i}× stacked vertically — each { ${seqDesc(chunks[i])} }${labels.length ? ` — ${labels.join(', ')}` : ''}`);
        count++;
      } else {
        for (const a of chunks[i]) walk(a, depth);
      }
      i = j;
    }
  };

  P(0, `PAGE ${Math.round(document.documentElement.scrollWidth)}×${Math.round(document.body.scrollHeight)}`);
  processChildren(document.body, 0);
  return out.join('\n');
} catch (e) { return 'SKELETON_ERROR: ' + ((e && e.message) || String(e)); } })();
