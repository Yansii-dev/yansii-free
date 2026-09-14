// tier-display.js — SINGLE SOURCE OF TRUTH for how a finding's tier maps to what the
// UI shows. Loaded by BOTH the dashboard and the DevTools panel so the two surfaces can
// never drift on the "no false criticals" promise.
//
// Three-tier system:
//   tier 1 = detected  (passive pattern match)      -> grey "potential", NO severity color
//   tier 2 = validated (active test suggests real)   -> yellow "review"
//   tier 3 = confirmed (proof / directly observable) -> real severity color + "observed"
// Only tier-3 findings count toward critical/high totals.
(function (root) {
  function tierDisplay(entry) {
    const tier = (entry && entry.tier) || 1;
    const sev = (entry && entry.finding && entry.finding.severity) || "info";
    const isT3 = tier === 3;
    return {
      tier,
      severity: sev,
      // CSS severity class for the coloured badge: tier-3 uses the REAL severity;
      // tier-2 is neutral "medium" (yellow); tier-1 is muted "info" (grey — never red).
      sevClass: isT3 ? sev : (tier === 2 ? "medium" : "info"),
      // text inside the severity badge
      sevText: isT3 ? sev : (tier === 2 ? "🔍 review" : "💤 potential"),
      // short status word
      label: isT3 ? "observed" : (tier === 2 ? "review" : "potential"),
      // only tier-3 crit/high are "real"
      isCritHigh: isT3 && (sev === "critical" || sev === "high"),
      countsCritical: isT3 && sev === "critical",
      countsHigh: isT3 && sev === "high",
      // P4: the CVSS/severity NUMBER is the loudest signal on a card — show it ONLY for
      // tier-3 (observed/confirmed). tier-1/tier-2 are unverified indicators: no scary score.
      showCvss: isT3,
      cvssText: (isT3 && entry && entry.cvss && entry.cvss.score != null) ? String(entry.cvss.score) : "",
    };
  }

  // Tally confirmed (tier-3) critical/high across a { domain: [entries] } map.
  function tierCounts(findingsByDomain) {
    let total = 0, confirmed = 0, crit = 0, high = 0;
    for (const d in (findingsByDomain || {})) {
      for (const e of (findingsByDomain[d] || [])) {
        if (e && e.verificationStatus === "false_positive") continue;
        total++;
        const disp = tierDisplay(e);
        if (disp.tier === 3) confirmed++;
        if (disp.countsCritical) crit++;
        if (disp.countsHigh) high++;
      }
    }
    return { total, confirmed, crit, high };
  }

  root.yansiiTierDisplay = tierDisplay;
  root.yansiiTierCounts = tierCounts;
})(typeof window !== "undefined" ? window : this);
