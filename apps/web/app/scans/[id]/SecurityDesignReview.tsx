"use client";

import type { SecurityReview } from "@/lib/api";

export function SecurityDesignReview({ review, pending }: { review?: SecurityReview; pending: boolean }) {
  const count = review?.suggestions.length ?? 0;
  const state = review?.status ?? "not_requested";
  const active = pending && (state === "running" || state === "not_requested");
  return (
    <section className="security-design-review" aria-label="AI security design review">
      <div className="specbox">
        <h3>AI security design review</h3>
        <p>DeepSeek suggests security improvements to your API and data model. These are design recommendations that need validation, separate from detected vulnerabilities.</p>
        {active ? <p role="status">The review is queued or running. Suggestions will appear here when it finishes.</p> : state === "unavailable" || state === "running" ? (
          <p role="status">The review could not finish. Check the AI configuration and input size, then open Run now and select Security design review under Choose AI passes.</p>
        ) : state === "not_requested" ? (
          <>
            <p>
              Open <strong>Run now</strong>, then enable <strong>Use AI</strong> or select
              <strong> Security design review</strong> under Choose AI passes. You can also use the CLI:
            </p>
            <pre className="shell"><code>runpentests run &lt;scan-id&gt; --authorized --security-review</code></pre>
            <p>Add and test a database schema connection in Inputs to compare it with the OpenAPI spec, or review the spec alone.</p>
          </>
        ) : (
          <p>
            {review?.schema_status === "available"
              ? "Compared OpenAPI with the configured database tables and constraints."
              : review?.schema_status === "unavailable"
                ? "OpenAPI only: the configured database metadata was unavailable."
                : "OpenAPI only: no database schema was provided."}
            {" "}{count} {count === 1 ? "suggestion" : "suggestions"}.
          </p>
        )}
      </div>
      {state === "completed" && review?.suggestions.length === 0 && (
        <p className="ai-note">No supported security design changes were identified in the supplied structure. This does not establish that the implementation is secure.</p>
      )}
      {review?.suggestions.map((item, index) => (
        <article className="design-suggestion" key={`${index}-${item.title}`}>
          <div className="fhead">
            <span className="ai-tag">{item.priority} priority</span>
            <h3>{item.title}</h3>
          </div>
          <dl>
            <dt>Observed in the schema</dt><dd>{item.observation}</dd>
            <dt>Security risk</dt><dd>{item.risk}</dd>
            <dt>Proposed change</dt><dd>{item.recommendation}</dd>
            <dt>How to validate</dt><dd>{item.validation}</dd>
          </dl>
          {item.assumptions.length > 0 && (
            <div><h4>Assumptions to check</h4><ul>{item.assumptions.map((text, i) => <li key={i}>{text}</li>)}</ul></div>
          )}
          <details className="ev">
            <summary>Schema references ({item.references.length})</summary>
            <ul>{item.references.map((ref) => <li key={ref}><code>{ref}</code></li>)}</ul>
          </details>
        </article>
      ))}
    </section>
  );
}
