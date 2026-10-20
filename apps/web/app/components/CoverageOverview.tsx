import Link from "next/link";
import { apiCoverage, GROUPS } from "@/lib/coverage";
import { TierChip } from "./TierChip";
import styles from "./CoverageOverview.module.css";

const FRIENDLY: Record<string, string> = {
  "API1:2023": "Other people’s data",
  "API2:2023": "Login and tokens",
  "API3:2023": "Private fields",
  "API4:2023": "Limits and abuse",
  "API5:2023": "Admin-only actions",
  "API6:2023": "Sensitive workflows",
  "API7:2023": "Server-side URL fetching",
  "API8:2023": "Security settings",
  "API9:2023": "Undocumented APIs",
  "API10:2023": "Upstream API trust",
};

export function CoverageOverview() {
  const areas = apiCoverage();
  const reached = areas.filter((area) => area.count > 0).length;
  const signals = GROUPS.flatMap((group) => group.checks);
  const implemented = signals.filter((signal) => signal.confidence !== "planned");
  const premium = implemented.filter((signal) => signal.premium).length;
  const standard = implemented.length - premium;
  const planned = signals.length - implemented.length;
  const categories = [
    { label: "Standard signals", count: standard, kind: styles.standard },
    { label: "Premium signals", count: premium, kind: styles.premium },
    { label: "Planned signals", count: planned, kind: styles.planned },
  ];

  return (
    <section className={`wrap section ${styles.overview}`} aria-labelledby="coverage-summary">
      <h2 id="coverage-summary" className="h-lg">The quick picture</h2>
      <p className={styles.intro}>
        We test common ways an API can expose data, trust the wrong user or handle
        input unsafely. Here is how broadly our available tests reach.
      </p>
      <div className={styles.summary}>
        <div className={styles.reach}>
          <svg viewBox="0 0 120 120" className={styles.ring} aria-hidden="true">
            <circle className={styles.track} cx="60" cy="60" r="48" />
            <circle className={styles.progress} cx="60" cy="60" r="48"
              pathLength="10" strokeDasharray={`${reached} ${areas.length - reached}`} />
            <text x="60" y="60" className={styles.ringNumber}>{reached}/{areas.length}</text>
            <text x="60" y="78" className={styles.ringLabel}>risk areas</text>
          </svg>
          <div>
            <h3>{reached} of {areas.length} API risk areas have tests</h3>
            <p>
              These are the OWASP API Top 10: ten common categories of API security
              risk. Each area below has at least one implemented signal when marked
              as available. Some risks within each area remain outside these tests.
            </p>
          </div>
        </div>
        <div className={styles.catalog}>
          <h3>{implemented.length} implemented test signals</h3>
          <p>One check can look for several signals. This shows the mix of available tests.</p>
          <div className={styles.bar} role="img"
            aria-label={categories.map((item) => `${item.count} ${item.label.toLowerCase()}`).join(", ")}>
            {categories.filter((item) => item.count > 0).map((item) => (
              <span key={item.label} className={item.kind} style={{ flexGrow: item.count }} />
            ))}
          </div>
          <dl className={styles.counts}>
            {categories.map((item) => (
              <div key={item.label}>
                <dt><i className={item.kind} aria-hidden="true" />{item.label}</dt>
                <dd>{item.count}</dd>
              </div>
            ))}
          </dl>
          <p className={styles.small}>Planned signals are documented ideas and do not run.</p>
        </div>
      </div>

      <div className={styles.map}>
        {areas.map((area, i) => (
          <article key={area.code}
            className={`${styles.area} ${area.best === "verified" ? styles.verified : area.best === "heuristic" ? styles.lead : styles.gap}`}>
            <span className={styles.areaNumber}>{String(i + 1).padStart(2, "0")}</span>
            <h3>{FRIENDLY[area.code] ?? area.name}</h3>
            <p>{area.count} implemented signal{area.count === 1 ? "" : "s"}</p>
            {area.best ? (
              <TierChip tier={area.best}>{area.best === "verified" ? "Proof possible" : "Leads only"}</TierChip>
            ) : <span className={styles.small}>No implemented signal</span>}
            {area.premiumOnly && <span className={styles.premiumNote}>Premium required</span>}
          </article>
        ))}
      </div>

      <div className={styles.explain}>
        <p><strong>Proof possible:</strong> at least one test in that area can directly demonstrate a weakness. <strong>Lead:</strong> a signal needs investigation.</p>
        <p><strong>For your scan:</strong> the API description, test logins and selected options decide which checks can run. Premium needs an enabled tenant and an explicit opt-in; some checks also need write permission or a callback service.</p>
        <p><strong>Known gaps:</strong> prompt injection, memory leaks and secrets hidden behind innocent field names are among the things we do not test.</p>
      </div>
      <div className={styles.links}>
        <Link className="btn" href="#check-details">Explore detailed checks</Link>
        <Link className="link-arrow" href="#coverage-gaps">See what is not covered →</Link>
      </div>
    </section>
  );
}
