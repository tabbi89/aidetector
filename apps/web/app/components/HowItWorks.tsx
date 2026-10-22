import Link from "next/link";

/** The actual setup sequence, without a second mock copy of the product UI. */
export function HowItWorks() {
  return (
    <div className="setup-map">
      <ol className="setup-steps">
        <li>
          <span className="setup-number" aria-hidden="true">
            01
          </span>
          <div>
            <h3>Map your API</h3>
            <p>Add a URL and an OpenAPI, Swagger, HAR or Postman file.</p>
            <code>api.example.com + openapi.yaml</code>
          </div>
        </li>
        <li>
          <span className="setup-number" aria-hidden="true">
            02
          </span>
          <div>
            <h3>Add test accounts</h3>
            <p>
              Use different accounts to compare data access and admin
              permissions.
            </p>
            <div className="identity-pair">
              <span>
                A <b>User</b>
              </span>
              <span aria-hidden="true">↔</span>
              <span>
                B <b>Admin / other tenant</b>
              </span>
            </div>
          </div>
        </li>
        <li>
          <span className="setup-number" aria-hidden="true">
            03
          </span>
          <div>
            <h3>Authorize &amp; run</h3>
            <p>
              Choose the level. Enable writes or AI only when you need them.
            </p>
            <span className="setup-result">
              → Findings + evidence + suggested fixes
            </span>
          </div>
        </li>
      </ol>
      <div className="setup-foot">
        <span>
          Public API? You can start without credentials; account-based checks
          need test logins.
        </span>
        <Link href="/scans/new">Start guided setup →</Link>
      </div>
    </div>
  );
}
