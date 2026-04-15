/**
 * Sudarshana — CVSS v3.1 base-score helpers.
 *
 * Parses a CVSS vector string and computes the base score the way
 * FIRST's spec says to. Kept here in a standalone module so the
 * assessment dashboard can render the score locally without a server
 * round-trip.
 */

// Metric value weights per CVSS v3.1 specification (§7.1).
const METRIC = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_unchanged: { N: 0.85, L: 0.62, H: 0.27 },
  PR_changed:   { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  S:  { U: "unchanged", C: "changed" },
  C:  { N: 0, L: 0.22, H: 0.56 },
  I:  { N: 0, L: 0.22, H: 0.56 },
  A:  { N: 0, L: 0.22, H: 0.56 },
};

/**
 * Parse a vector of the form:
 *   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 * Returns an object keyed by metric code.
 */
export function parseVector(vector) {
  const parts = vector.split("/").slice(1);
  const out = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (k && v) out[k] = v;
  }
  return out;
}

function roundUp(x) {
  // CVSS "roundup": round to 1 decimal place, always toward +∞.
  return Math.ceil(x * 10) / 10;
}

/** Compute the CVSS v3.1 base score from a parsed vector. */
export function baseScore(metrics) {
  const scope = metrics.S === "C" ? "changed" : "unchanged";
  const pr = scope === "changed" ? METRIC.PR_changed : METRIC.PR_unchanged;

  const iscBase =
    1 - (1 - METRIC.C[metrics.C]) * (1 - METRIC.I[metrics.I]) * (1 - METRIC.A[metrics.A]);

  const isc =
    scope === "unchanged"
      ? 6.42 * iscBase
      : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  const exploitability =
    8.22 * METRIC.AV[metrics.AV] * METRIC.AC[metrics.AC] * pr[metrics.PR] * METRIC.UI[metrics.UI];

  if (isc <= 0) return { base: 0, severity: "None", impact: isc, exploitability };

  const raw =
    scope === "unchanged"
      ? Math.min(isc + exploitability, 10)
      : Math.min(1.08 * (isc + exploitability), 10);

  const base = roundUp(raw);
  return { base, severity: severityOf(base), impact: isc, exploitability };
}

export function severityOf(score) {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

/** One-shot: parse + score a full vector string. */
export function score(vector) {
  return baseScore(parseVector(vector));
}
