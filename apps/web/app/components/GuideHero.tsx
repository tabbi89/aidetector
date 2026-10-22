import Link from "next/link";
import { ScannerBot } from "./HeroStage";
import styles from "./GuideHero.module.css";

const CONTENT = {
  coverage: {
    eyebrow: "Test coverage",
    title: "Know what a scan can tell you.",
    lead: "Follow the evidence from a request to a result. Explore the checks, understand their signals and see where testing stops.",
    action: "Explore checks",
    href: "#check-details",
    secondary: "Read the evidence",
    secondaryHref: "#evidence-guide",
    caption:
      "Illustrative scan: account access, risky input and security settings are checked, producing verified evidence, leads to investigate and explicit gaps.",
  },
  cli: {
    eyebrow: "CLI guide",
    title: "Your terminal. The same evidence.",
    lead: "Run scans from your machine, add source context and bring security checks into CI. Browser and CLI runs share one scan history.",
    action: "Install the CLI",
    href: "#install",
    secondary: "Project setup",
    secondaryHref: "#project",
    caption:
      "Illustrative CLI workflow: a target and project configuration go through the scanner to findings, request evidence and reports in the same scan history.",
  },
} as const;

/** Guide-specific diagrams reuse the homepage's scanner and visual vocabulary. */
export function GuideHero({ kind }: { kind: keyof typeof CONTENT }) {
  const content = CONTENT[kind];
  return (
    <section className={styles.hero}>
      <div className={`wrap ${styles.layout}`}>
        <div className={styles.copy}>
          <div className={styles.eyebrow}>{content.eyebrow}</div>
          <h1>{content.title}</h1>
          <p className="lead">{content.lead}</p>
          <div className="hero-cta">
            <Link className="btn" href={content.href}>
              {content.action}
            </Link>
            <Link className="link-arrow" href={content.secondaryHref}>
              {content.secondary} →
            </Link>
          </div>
        </div>
        <figure
          className={`stage ${styles.illustration}`}
          aria-labelledby={`${kind}-hero-caption`}
        >
          <figcaption id={`${kind}-hero-caption`} className="sr-only">
            {content.caption}
          </figcaption>
          <span className={styles.tag}>Illustrative example</span>
          <div className={styles.diagram} aria-hidden="true">
            <div className={styles.input}>
              <span className={styles.panelTitle}>
                {kind === "coverage" ? "Your API" : "Your project"}
              </span>
              {kind === "coverage" ? (
                <>
                  <div className={styles.route}>
                    <b>GET</b>
                    <code>/orders/&#123;id&#125;</code>
                  </div>
                  <div className={styles.route}>
                    <b>GET</b>
                    <code>/search?q=…</code>
                  </div>
                  <div className={styles.accounts}>
                    <span>A</span>
                    <i>↔</i>
                    <span>B</span>
                    <small>Compare access</small>
                  </div>
                </>
              ) : (
                <>
                  <div className={styles.command}>
                    <span>$</span> runpentests
                    <br />
                    api.example.com
                  </div>
                  <div className={styles.file}>↳ runpentests.yml</div>
                  <span className={styles.local}>
                    Local network · source · CI
                  </span>
                </>
              )}
            </div>
            <div className={styles.scanner}>
              <ScannerBot idPrefix={`${kind}-bot`} />
            </div>
            <div className={styles.output}>
              <span className={styles.panelTitle}>
                {kind === "coverage" ? "Read the result" : "One scan history"}
              </span>
              {kind === "coverage" ? (
                <>
                  <div className={styles.result}>
                    <span className={styles.proof}>✓ Verified</span>
                    <small>Weakness demonstrated</small>
                  </div>
                  <div className={styles.result}>
                    <span className={styles.lead}>◐ Lead</span>
                    <small>Investigate the signal</small>
                  </div>
                  <div className={styles.result}>
                    <span>— Not tested</span>
                    <small>Review the gap</small>
                  </div>
                </>
              ) : (
                <>
                  <div className={styles.result}>
                    <span className={styles.proof}>↳ Findings</span>
                    <small>Impact and confidence</small>
                  </div>
                  <div className={styles.result}>
                    <span>↔ Evidence</span>
                    <small>Requests and responses</small>
                  </div>
                  <div className={styles.result}>
                    <span>↓ Reports</span>
                    <small>Share and retest</small>
                  </div>
                </>
              )}
            </div>
          </div>
          <div className={styles.foot}>
            {kind === "coverage"
              ? "Request → observation → next step"
              : "Terminal → scanner → shared results"}
          </div>
        </figure>
      </div>
    </section>
  );
}
