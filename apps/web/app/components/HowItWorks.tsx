import Link from "next/link";
import styles from "./HowItWorks.module.css";

function SetupIcon({
  name,
}: {
  name: "file" | "user" | "check" | "arrow" | "key" | "evidence" | "fix";
}) {
  const paths = {
    file: (
      <>
        <path d="M14 3H6v18h12V7z" />
        <path d="M14 3v5h4M9 12h6M9 16h4" />
      </>
    ),
    user: (
      <>
        <circle cx="12" cy="8" r="3" />
        <path d="M5 21v-2a7 7 0 0 1 14 0v2" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
    key: (
      <>
        <circle cx="8" cy="9" r="4" />
        <path d="m11 12 8 8m-4-4 3-3m-6 0 3-3" />
      </>
    ),
    evidence: (
      <>
        <path d="M5 4h14v16H5zM8 8h8m-8 4h8m-8 4h5" />
      </>
    ),
    fix: (
      <>
        <path d="m8 4-5 8 5 8m8-16 5 8-5 8m-3-15-2 14" />
      </>
    ),
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

/** Static teaching diagrams: setup and scanning happen in the linked wizard. */
export function HowItWorks() {
  return (
    <div className={styles.map}>
      <div className={styles.caption}>
        <span className={styles.captionMark} aria-hidden="true">
          ↳
        </span>
        Your setup becomes a test plan
        <span className={styles.example}>Illustrative workflow</span>
      </div>
      <ol className={styles.steps} aria-label="Scan setup steps">
        <li className={styles.step}>
          <div className={styles.stepHeading}>
            <span className={styles.number} aria-hidden="true">
              01
            </span>
            <h3>Map your API</h3>
          </div>
          <p className={styles.description}>
            Add a URL and an OpenAPI, Swagger, HAR or Postman file.
          </p>
          <figure
            className={styles.visual}
            aria-label="Example: an API URL and description map to GET and POST endpoints."
          >
            <div className={styles.address}>
              <span className={styles.addressMark} aria-hidden="true">
                ↗
              </span>
              <code>api.example.com</code>
            </div>
            <div className={styles.source}>
              <span className={styles.fileIcon}>
                <SetupIcon name="file" />
              </span>
              <div>
                <strong>API description</strong>
                <span>OpenAPI · Swagger · HAR · Postman</span>
              </div>
            </div>
            <div className={styles.routes}>
              <div>
                <span className={styles.get}>GET</span>
                <code>/projects</code>
              </div>
              <div>
                <span className={styles.get}>GET</span>
                <code>/projects/&#123;id&#125;</code>
              </div>
              <div>
                <span className={styles.post}>POST</span>
                <code>/projects</code>
              </div>
            </div>
          </figure>
          <span className={styles.connector} aria-hidden="true">
            <SetupIcon name="arrow" />
          </span>
        </li>
        <li className={styles.step}>
          <div className={styles.stepHeading}>
            <span className={styles.number} aria-hidden="true">
              02
            </span>
            <h3>Add test accounts</h3>
          </div>
          <p className={styles.description}>
            Use different accounts to compare data access and admin permissions.
          </p>
          <figure
            className={`${styles.visual} ${styles.identityVisual}`}
            aria-label="Example: two test accounts send requests to the same endpoint to compare access. Use different roles or tenants for the relevant checks."
          >
            <div className={styles.accounts}>
              <div className={styles.account}>
                <span className={styles.avatar}>
                  <SetupIcon name="user" />
                  <b>A</b>
                </span>
                <strong>Account A</strong>
                <span className={styles.credential}>
                  <SetupIcon name="key" />
                  ••••••••
                </span>
              </div>
              <div className={styles.account}>
                <span className={`${styles.avatar} ${styles.alternate}`}>
                  <SetupIcon name="user" />
                  <b>B</b>
                </span>
                <strong>Account B</strong>
                <span className={styles.credential}>
                  <SetupIcon name="key" />
                  ••••••••
                </span>
              </div>
            </div>
            <div className={styles.merge} aria-hidden="true">
              <span>↓</span>
            </div>
            <div className={styles.endpoint}>
              <span className={styles.get}>GET</span>
              <code>/projects/&#123;id&#125;</code>
            </div>
            <figcaption className={styles.visualNote}>
              Different roles or different tenants
            </figcaption>
          </figure>
          <span className={styles.connector} aria-hidden="true">
            <SetupIcon name="arrow" />
          </span>
        </li>
        <li className={styles.step}>
          <div className={styles.stepHeading}>
            <span className={styles.number} aria-hidden="true">
              03
            </span>
            <h3>Authorize &amp; run</h3>
          </div>
          <p className={styles.description}>
            Choose the level. Enable writes or AI only when you need them.
          </p>
          <figure
            className={`${styles.visual} ${styles.runVisual}`}
            aria-label="Authorization is required to run. Writes and AI start off. Results include findings, evidence and suggested fixes."
          >
            <div className={styles.authorization}>
              <SetupIcon name="check" />
              <strong>Authorization required</strong>
            </div>
            <div className={styles.options}>
              <span>
                <i aria-hidden="true" />
                Writes <b>Off</b>
              </span>
              <span>
                <i aria-hidden="true" />
                AI <b>Off</b>
              </span>
            </div>
            <div className={styles.outputs}>
              <div>
                <span className={styles.findingMark} aria-hidden="true">
                  !
                </span>
                <strong>Findings</strong>
                <span>What to review</span>
              </div>
              <div>
                <SetupIcon name="evidence" />
                <strong>Evidence</strong>
                <span>What happened</span>
              </div>
              <div>
                <SetupIcon name="fix" />
                <strong>Suggested fixes</strong>
                <span>What to change</span>
              </div>
            </div>
          </figure>
        </li>
      </ol>
      <div className={styles.footer}>
        <p>
          <span className={styles.info} aria-hidden="true">
            i
          </span>
          <span>
            Public API? Start without credentials. Account-based checks need
            test logins.
          </span>
        </p>
        <Link href="/scans/new">
          Start guided setup <SetupIcon name="arrow" />
        </Link>
      </div>
    </div>
  );
}
