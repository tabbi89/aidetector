import Link from "next/link";

/**
 * The landing hero's illustration: one illustrative scan, told in panels.
 *
 * Left, what the engine works with (endpoints, the two test identities, the
 * request trace, findings). Centre, the scanner probing them. Right, the
 * optional AI adjudication walking the evidence chain to a verdict. Every
 * value is invented for the picture; the figure says so. Motion is CSS only
 * and stops under prefers-reduced-motion (the global rule in globals.css).
 */
export function HeroStage() {
  return (
    <figure className="stage" aria-labelledby="stage-caption">
      <figcaption id="stage-caption" className="sr-only">
        Illustration of an example scan: the scanner probes each endpoint as two test users,
        records every request, and the AI adjudication confirms that one user can read another
        user&rsquo;s order.
      </figcaption>
      <span className="stage-tag" aria-hidden="true">Example scan · illustrative</span>

      <div className="stage-grid" aria-hidden="true">
        <div className="stage-panels">
          <section className="sc sc-endpoints">
            <h3>Endpoints</h3>
            <ul>
              <li><b className="m get">GET</b><code>/orders/{"{id}"}</code><i className="d hot" /></li>
              <li><b className="m post">POST</b><code>/orders</code><i className="d ok" /></li>
              <li><b className="m get">GET</b><code>/search</code><i className="d warn" /></li>
              <li><b className="m del">DEL</b><code>/users/{"{id}"}</code><i className="d idle" /></li>
            </ul>
          </section>

          <section className="sc sc-identities">
            <h3>Identities</h3>
            <div className="who">
              <span className="avatar a">A</span>
              <span className="who-name">alice<small>owner</small></span>
            </div>
            <div className="who-link"><span /></div>
            <div className="who">
              <span className="avatar b">B</span>
              <span className="who-name">bob<small>other user</small></span>
            </div>
          </section>

          <section className="sc sc-trace">
            <h3>Request trace</h3>
            <ol>
              <li><span className="seq">#11</span><code>POST /orders</code><span className="st ok">201</span></li>
              <li><span className="seq">#12</span><code>GET /orders/1042</code><span className="st ok">200</span></li>
              <li className="hit"><span className="seq">#13</span><code>GET /orders/1042</code><span className="st hot">200</span></li>
              <li><span className="seq">#14</span><code>GET /search?q=</code><span className="st warn">200</span></li>
            </ol>
            <span className="scanline" />
          </section>

          <section className="sc sc-findings">
            <h3>Findings</h3>
            <div className="fr"><span className="sev high">high</span><span className="bar w80" /><span className="tier v">verified</span></div>
            <div className="fr"><span className="sev med">med</span><span className="bar w55" /><span className="tier l">lead</span></div>
            <div className="fr"><span className="sev low">low</span><span className="bar w35" /><span className="tier l">lead</span></div>
          </section>
        </div>

        <div className="stage-bot">
          <span className="beam beam-probe" />
          <span className="beam beam-report" />
          <ScannerBot />
        </div>

        <section className="sc sc-ai">
          <h3>AI adjudication</h3>
          <p className="ai-subject"><span className="sev high">high</span> Broken object-level authorization</p>
          <p className="ai-route"><code>GET /orders/{"{id}"}</code></p>
          <div className="ai-reason">
            <span>Reasoning</span>
            <i className="ln l1" /><i className="ln l2" />
          </div>
          <h4>Evidence chain</h4>
          <ol className="chain">
            <li><span className="ci">1</span>alice creates order <code>1042</code></li>
            <li><span className="ci">2</span>bob requests <code>/orders/1042</code></li>
            <li><span className="ci">3</span>API returns alice&rsquo;s order to bob</li>
            <li className="verdict"><span className="ci">✓</span>Confirmed · verified evidence</li>
          </ol>
          <p className="ai-fix">Fix: check the caller owns the order before returning it.</p>
        </section>
      </div>

      <Link className="stage-link" href="#results">Where do I find my results? →</Link>
    </figure>
  );
}

/** The scanner, drawn on the favicon's shield. Pure shapes; colours from CSS. */
function ScannerBot() {
  return (
    <svg className="bot" viewBox="0 0 300 360" role="presentation" focusable="false">
      <defs>
        <clipPath id="bot-visor-clip">
          <rect x="114" y="76" width="72" height="24" rx="12" />
        </clipPath>
        <radialGradient id="bot-halo-grad">
          <stop offset="0" className="g-halo-in" />
          <stop offset="1" className="g-halo-out" />
        </radialGradient>
        <linearGradient id="bot-suit-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" className="g-suit-top" />
          <stop offset="1" className="g-suit-bottom" />
        </linearGradient>
      </defs>

      <circle cx="150" cy="180" r="150" fill="url(#bot-halo-grad)" />
      <g className="bot-orbits">
        <ellipse className="bot-orbit" cx="150" cy="180" rx="142" ry="142" />
        <circle className="bot-packet" cx="8" cy="180" r="4" />
        <circle className="bot-packet hot" cx="292" cy="180" r="4" />
        <circle className="bot-packet" cx="150" cy="38" r="3" />
      </g>
      <ellipse className="bot-shadow" cx="150" cy="340" rx="78" ry="9" />

      <g className="bot-body">
        {/* pack and legs */}
        <rect className="bot-dark" x="94" y="148" width="112" height="112" rx="24" />
        <rect className="bot-suit" x="116" y="244" width="30" height="64" rx="13" />
        <rect className="bot-suit" x="154" y="244" width="30" height="64" rx="13" />
        <rect className="bot-dark" x="102" y="298" width="48" height="22" rx="10" />
        <rect className="bot-dark" x="150" y="298" width="48" height="22" rx="10" />
        <rect className="bot-trim" x="110" y="300" width="14" height="4" rx="2" />
        <rect className="bot-trim" x="176" y="300" width="14" height="4" rx="2" />

        {/* torso */}
        <rect fill="url(#bot-suit-grad)" x="100" y="138" width="100" height="120" rx="30" />
        <rect className="bot-dark" x="104" y="226" width="92" height="12" rx="6" />
        <rect className="bot-visor" x="122" y="166" width="56" height="42" rx="9" />
        <rect className="bot-ok bar b1" x="130" y="184" width="8" height="18" rx="2" />
        <rect className="bot-warn bar b2" x="142" y="184" width="8" height="18" rx="2" />
        <rect className="bot-hot bar b3" x="154" y="184" width="8" height="18" rx="2" />
        <rect className="bot-trim bar b4" x="166" y="184" width="6" height="18" rx="2" />

        {/* left arm and the probe */}
        <path className="bot-limb" d="M106 162 C84 170 72 182 66 198" />
        <rect className="bot-dark" x="12" y="184" width="60" height="26" rx="7" />
        <rect className="bot-trim" x="22" y="190" width="22" height="6" rx="3" />
        <rect className="bot-dark" x="44" y="206" width="14" height="22" rx="4" />
        <rect className="bot-trim" x="0" y="190" width="16" height="14" rx="4" />
        <circle className="bot-hot pulse" cx="4" cy="197" r="5" />
        <circle className="bot-hand" cx="64" cy="202" r="12" />

        {/* right arm and the report */}
        <path className="bot-limb" d="M194 162 C216 172 228 186 234 202" />
        <rect className="bot-dark" x="232" y="176" width="54" height="66" rx="8" />
        <rect className="bot-visor" x="238" y="184" width="42" height="44" rx="4" />
        <rect className="bot-ok" x="244" y="192" width="22" height="4" rx="2" />
        <rect className="bot-ok-dim" x="244" y="201" width="30" height="4" rx="2" />
        <rect className="bot-ok-dim" x="244" y="210" width="16" height="4" rx="2" />
        <path className="bot-check" d="M262 216 l5 5 l9 -11" />
        <circle className="bot-hand" cx="236" cy="206" r="12" />

        {/* head */}
        <rect className="bot-dark" x="136" y="126" width="28" height="18" rx="6" />
        <line className="bot-antenna" x1="150" y1="40" x2="150" y2="16" />
        <circle className="bot-hot pulse" cx="150" cy="12" r="6" />
        <path
          className="bot-head"
          d="M150 36 L202 57 V92 C202 119 180 137 150 148 C120 137 98 119 98 92 V57 Z"
        />
        <path
          className="bot-rim"
          d="M150 46 L193 63 V92 C193 113 176 128 150 137 C124 128 107 113 107 92 V63 Z"
        />
        <rect className="bot-visor" x="114" y="76" width="72" height="24" rx="12" />
        <g clipPath="url(#bot-visor-clip)">
          <rect className="bot-ok-dim" x="114" y="86" width="72" height="4" />
          <rect className="bot-scan" x="114" y="76" width="18" height="24" />
        </g>
      </g>
    </svg>
  );
}
