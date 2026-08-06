// uxlint secret/PII redaction — THE single source of truth.
//
// This snippet is the ONLY place the redaction patterns are written. It is interpolated verbatim
// into every browser-side capture channel at injection time — the page collector (collector.js),
// the pre-screenshot DOM mask (worker.rs `mask_secrets_js`), and the goal-walk harvest
// (goals_walk.rs `harvest_js`) — so those channels cannot drift apart. The Rust console/dialog
// redactor (redact.rs `redact_secrets`) mirrors the same patterns for the two channels that never
// touch the DOM, and a test (`redact.rs` tests) asserts every channel masks the same corpus.
//
// BEST-EFFORT, NOT A GUARANTEE. This is a pattern-based backstop: it masks text that LOOKS like a
// known token/API-key/password/email. Unusual token shapes, split-up values, and arbitrary
// sensitive DATA (customer names, addresses, order contents) cannot be pattern-matched and are NOT
// caught. Audit test/staging accounts with synthetic data; see README "Privacy & trust".
//
// When interpolated it declares, in the enclosing scope: `UXLINT_SECRET_RES`, `UXLINT_SECRET_LAB`,
// `UXLINT_EMAIL_RE`, and the function `uxlintRedact(text) -> string`. Each channel aliases
// `uxlintRedact` to its own local name.
const UXLINT_SECRET_RES = [
	// Stripe / OpenAI / Anthropic-style prefixed keys: sk_live_…, rk_test_…, pk_…
	/\b(?:sk|rk|pk)[-_](?:live|test|prod|proj)?[-_]?[A-Za-z0-9]{16,}\b/g,
	// GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ and the fine-grained github_pat_ form.
	/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
	/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
	// Slack tokens: xoxb-/xoxa-/xoxp-/xoxr-/xoxs-.
	/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
	// AWS access key id.
	/\bAKIA[0-9A-Z]{16}\b/g,
	// Google API key.
	/\bAIza[0-9A-Za-z_-]{35}\b/g,
	// GitLab personal access token.
	/\bglpat-[A-Za-z0-9_-]{20,}\b/g,
	// JWT (three base64url segments) — session/bearer tokens routinely rendered in UIs.
	/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g,
	// A bare `Bearer <token>` header value.
	/\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/gi,
	// A PEM private-key block (any label: RSA/EC/OPENSSH/…), start-to-end.
	/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];
// A long value right after an explicit secret label — keep the label, redact the value.
const UXLINT_SECRET_LAB = /\b(api[\s_-]?key|secret|token|password|passwd|access[\s_-]?key|client[\s_-]?secret)\b(["'\s:=]{1,4})([A-Za-z0-9._~+/-]{12,}=*)/gi;
// Email addresses are PII and pattern-matchable. Version strings (react@18.2.0) don't match — the
// TLD must be >=2 letters. Site contact emails get redacted too; the report keeps the mailto link.
const UXLINT_EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
function uxlintRedact(t) {
	if (!t) return t;
	let out = t;
	for (const re of UXLINT_SECRET_RES) out = out.replace(re, '[redacted]');
	out = out.replace(UXLINT_SECRET_LAB, (_m, label, sep) => label + sep + '[redacted]');
	return out.replace(UXLINT_EMAIL_RE, '[email]');
}
