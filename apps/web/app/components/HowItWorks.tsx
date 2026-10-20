/**
 * "How it works" as one picture: the browser lane and the terminal lane, each
 * three steps in mock product cards, both landing on the same scan page.
 *
 * Hand-maintained like Flow.tsx. The web cards mirror RunPanel and
 * CredentialsPanel, the terminal cards mirror the commands in the CLI section
 * and cli/README.md. If those change, this changes with them.
 */

import Link from "next/link";
import { TierChip } from "./TierChip";

export function HowItWorks() {
  return (
    <figure className="hiw">
      <figcaption className="hiw-caption">Illustrative example</figcaption>

      <div className="hiw-lane">
        <header className="hiw-head">
          <span className="hiw-chip web" aria-hidden="true">web</span>
          <div>
            <h3>In the browser</h3>
            <p>Guided setup — nothing to install.</p>
          </div>
        </header>

        <ol className="hiw-steps">
          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">01</span>
              <h4>Describe the API</h4>
            </div>
            <p>
              Enter the address and add the file that lists the endpoints:
              OpenAPI, Swagger, a Postman collection or a HAR capture.
            </p>
            <div className="hiw-shot" aria-hidden="true">
              <div className="hiw-shot-head">
                <span>New scan</span>
                <span className="hiw-tag">step 1 of 3</span>
              </div>
              <div className="hiw-field">
                <span>API URL</span>
                <b>https://api.example.com</b>
              </div>
              <div className="hiw-file">
                <b>openapi.yaml</b>
                <span>OpenAPI 3.1</span>
              </div>
            </div>
            <p className="hiw-status ok"><i aria-hidden="true" />Scan created</p>
          </li>

          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">02</span>
              <h4>Add test logins</h4>
            </div>
            <p>
              Say how it signs in — public, one key, or several roles. With a
              normal user and an admin, authorization bugs show in the difference
              between what each can reach. Secrets are encrypted at rest.
            </p>
            <div className="hiw-shot" aria-hidden="true">
              <div className="hiw-shot-head">
                <span>Test logins</span>
                <span className="hiw-tag">encrypted</span>
              </div>
              <div className="hiw-id">
                <i className="hiw-dot user" />
                <div>
                  <b>alice</b>
                  <span>normal user</span>
                </div>
              </div>
              <div className="hiw-id">
                <i className="hiw-dot admin" />
                <div>
                  <b>admin</b>
                  <span>administrator</span>
                </div>
              </div>
            </div>
            <p className="hiw-status ok"><i aria-hidden="true" />2 identities sealed</p>
          </li>

          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">03</span>
              <h4>Authorize &amp; run</h4>
            </div>
            <p>
              Pick Quick or Standard, switch on writes or AI if you want them,
              confirm you may test the host, and start. The engine stays inside
              its request budget.
            </p>
            <div className="hiw-shot" aria-hidden="true">
              <div className="hiw-shot-head">
                <span>Run scan</span>
                <span className="hiw-tag">Standard</span>
              </div>
              <div className="hiw-opt">
                <i className="on" />
                <span>Test writes</span>
                <em>mutates data</em>
              </div>
              <div className="hiw-opt">
                <i />
                <span>Use AI</span>
                <em>spends tokens</em>
              </div>
              <div className="hiw-consent">
                <i className="on" />
                <span>I may test this host</span>
              </div>
              <div className="hiw-btn">Run scan</div>
            </div>
            <p className="hiw-status warn"><i aria-hidden="true" />403 without consent</p>
          </li>
        </ol>
      </div>

      <div className="hiw-lane">
        <header className="hiw-head">
          <span className="hiw-chip cli" aria-hidden="true">cli</span>
          <div>
            <h3>In the terminal</h3>
            <p>One static binary — the same API the web uses.</p>
          </div>
        </header>

        <ol className="hiw-steps">
          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">01</span>
              <h4>Connect once</h4>
            </div>
            <p>
              The key is prompted for or read from stdin — never a flag, so it
              never lands in shell history. CI supplies it as an environment
              variable.
            </p>
            <div className="hiw-term" aria-hidden="true">
              <div><span className="p">$</span> aidetector login</div>
              <div><span className="c">API key · stored 0600</span></div>
            </div>
            <p className="hiw-status ok"><i aria-hidden="true" />Key stored 0600</p>
          </li>

          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">02</span>
              <h4>Point it at an API</h4>
            </div>
            <p>
              It reuses the scan you already have for that host — identities,
              triage and history included — or creates one, finds the spec, runs,
              and prints what it found.
            </p>
            <div className="hiw-term" aria-hidden="true">
              <div><span className="p">$</span> aidetector https://api.example.com</div>
              <div><span className="c">spec · /openapi.json</span></div>
              <div><span className="c">scan 4f2a · running</span></div>
            </div>
            <p className="hiw-status ok"><i aria-hidden="true" />Scan 4f2a started</p>
          </li>

          <li className="hiw-step">
            <div className="hiw-step-head">
              <span className="hiw-n" aria-hidden="true">03</span>
              <h4>Go deeper, or local</h4>
            </div>
            <p>
              The Deep level and your own source are one argument away, off until
              you ask. Settings can live in a committed aidetector.yml.
            </p>
            <div className="hiw-term" aria-hidden="true">
              <div><span className="p">$</span> aidetector https://api.example.com . \</div>
              <div>{"    "}<span className="a">--authorized --agent --fail-on high</span></div>
              <div><span className="c">4 findings · 2 verified</span></div>
            </div>
            <p className="hiw-status warn"><i aria-hidden="true" />Exit 1 on new high</p>
          </li>
        </ol>
      </div>

      <div className="hiw-merge" aria-hidden="true">
        <span>Both lanes land here</span>
      </div>

      <div className="hiw-result">
        <div className="hiw-result-head">
          <div>
            <span className="hiw-tag">Scan results</span>
            <h3>One scan page for both lanes</h3>
          </div>
          <span className="st-chip completed">Completed</span>
        </div>
        <div className="hiw-result-body">
          <div>
            <div className="hiw-sum">
              <b>2 findings</b>
              <span>1 verified · 1 lead to investigate</span>
            </div>
            <div className="hiw-finding">
              <span className="sev-badge high">high</span>
              <TierChip tier="verified">verified</TierChip>
              <b>A user can read another account’s order</b>
              <code>GET /orders/{"{id}"}</code>
            </div>
            <div className="hiw-finding lead">
              <TierChip tier="heuristic">lead</TierChip>
              <span>Search echoes attack-like input. Investigate before treating it as a bug.</span>
            </div>
          </div>
          <ul className="hiw-same">
            <li>Same fingerprints, triage and run-to-run diff</li>
            <li>Same request log and endpoint coverage</li>
            <li>PDF · HTML · Markdown · JSON · SARIF exports</li>
          </ul>
        </div>
        <div className="hiw-result-foot">
          <span>One server. One history. Either way in.</span>
          <Link href="/scans">Open your scans →</Link>
        </div>
      </div>
    </figure>
  );
}
