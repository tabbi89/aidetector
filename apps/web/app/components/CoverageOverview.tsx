import Link from "next/link";
import { COVERAGE_LABELS } from "@/lib/coverageLabels";
import { apiCoverage, GROUPS } from "@/lib/coverage";
import { TierChip } from "./TierChip";
import styles from "./CoverageOverview.module.css";

export function CoverageOverview() {
  const areas = apiCoverage();
  const reached = areas.filter((area) => area.count > 0).length;
  const signals = GROUPS.flatMap((group) => group.checks);
  const implemented = signals.filter(
    (signal) => signal.confidence !== "planned",
  );
  const premium = implemented.filter((signal) => signal.premium).length;
  const standard = implemented.length - premium;
  const planned = signals.length - implemented.length;
  const categories = [
    { label: "Standard signals", count: standard, kind: styles.standard },
    { label: "Premium signals", count: premium, kind: styles.premium },
    { label: "Planned signals", count: planned, kind: styles.planned },
  ];

  return (
    <section
      className={`wrap section ${styles.overview}`}
      aria-labelledby="coverage-summary"
    >
      <h2 id="coverage-summary" className="h-lg">
        The quick picture
      </h2>
      <p className={styles.intro}>
        Available signals across the OWASP API Top 10. A risk area with tests is
        not a guarantee of full coverage.
      </p>
      <div className={styles.summary}>
        <div className={styles.reach}>
          <svg viewBox="0 0 120 120" className={styles.ring} aria-hidden="true">
            <circle className={styles.track} cx="60" cy="60" r="48" />
            <circle
              className={styles.progress}
              cx="60"
              cy="60"
              r="48"
              pathLength="10"
              strokeDasharray={`${reached} ${areas.length - reached}`}
            />
            <text x="60" y="60" className={styles.ringNumber}>
              {reached}/{areas.length}
            </text>
            <text x="60" y="78" className={styles.ringLabel}>
              risk areas
            </text>
          </svg>
          <div>
            <h3>
              {reached} of {areas.length} API risk areas have tests
            </h3>
            <p>
              At least one signal per marked area. Your API, accounts and run
              options determine which checks can run.
            </p>
          </div>
        </div>
        <div className={styles.catalog}>
          <h3>{implemented.length} implemented test signals</h3>
          <p>A check can look for more than one signal.</p>
          <div
            className={styles.bar}
            role="img"
            aria-label={categories
              .map((item) => `${item.count} ${item.label.toLowerCase()}`)
              .join(", ")}
          >
            {categories
              .filter((item) => item.count > 0)
              .map((item) => (
                <span
                  key={item.label}
                  className={item.kind}
                  style={{ flexGrow: item.count }}
                />
              ))}
          </div>
          <dl className={styles.counts}>
            {categories.map((item) => (
              <div key={item.label}>
                <dt>
                  <i className={item.kind} aria-hidden="true" />
                  {item.label}
                </dt>
                <dd>{item.count}</dd>
              </div>
            ))}
          </dl>
          {planned > 0 && (
            <p className={styles.small}>Planned signals do not run.</p>
          )}
        </div>
      </div>

      <div className={styles.map}>
        {areas.map((area, i) => (
          <a
            key={area.code}
            href={`?risk=${encodeURIComponent(area.code)}#check-details`}
            className={`${styles.area} ${area.best === "verified" ? styles.verified : area.best === "heuristic" ? styles.lead : styles.gap}`}
          >
            <span className={styles.areaNumber}>
              {String(i + 1).padStart(2, "0")}
            </span>
            <h3>{COVERAGE_LABELS[area.code] ?? area.name}</h3>
            <p>
              {area.count} signal{area.count === 1 ? "" : "s"}{" "}
              <span aria-hidden="true">↗</span>
            </p>
            {area.best ? (
              <TierChip tier={area.best}>
                {area.best === "verified" ? "Proof possible" : "Leads only"}
              </TierChip>
            ) : (
              <span className={styles.small}>No implemented signal</span>
            )}
            {area.premiumOnly && (
              <span className={styles.premiumNote}>Premium required</span>
            )}
          </a>
        ))}
      </div>

      <p className={styles.explain}>
        <strong>Proof possible</strong> means at least one signal can
        demonstrate a weakness. <strong>Leads only</strong> means investigation
        is still needed. Open an area to explore its checks.
      </p>
      <div className={styles.links}>
        <Link className="btn" href="#check-details">
          Explore detailed checks
        </Link>
        <Link className="link-arrow" href="#coverage-gaps">
          See what is not covered →
        </Link>
      </div>
    </section>
  );
}
