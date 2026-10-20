"use client";

import { Fragment, type ReactNode, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

/**
 * Render the model's lightweight markdown as React nodes — never via
 * dangerouslySetInnerHTML, so the target-derived text stays inert (React
 * escapes it). Handles paragraphs, `code` spans, **bold**, and -/1. lists,
 * which is all the answer prose uses.
 */
function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      nodes.push(<code key={key++}>{tok.slice(1, -1)}</code>);
    } else {
      nodes.push(<strong key={key++}>{tok.slice(2, -2)}</strong>);
    }
    last = re.lastIndex;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function renderRich(text: string): ReactNode {
  return text
    .trim()
    .split(/\n\s*\n/)
    .map((block, i) => {
      const lines = block.split("\n").filter((l) => l.trim() !== "");
      if (lines.length && lines.every((l) => /^\s*[-*]\s+/.test(l))) {
        return (
          <ul key={i}>
            {lines.map((l, j) => (
              <li key={j}>{renderInline(l.replace(/^\s*[-*]\s+/, ""))}</li>
            ))}
          </ul>
        );
      }
      if (lines.length && lines.every((l) => /^\s*\d+\.\s+/.test(l))) {
        return (
          <ol key={i}>
            {lines.map((l, j) => (
              <li key={j}>{renderInline(l.replace(/^\s*\d+\.\s+/, ""))}</li>
            ))}
          </ol>
        );
      }
      return <p key={i}>{renderInline(lines.join(" "))}</p>;
    })
    .map((node, i) => <Fragment key={i}>{node}</Fragment>);
}

/**
 * "Ask your scan" — a premium natural-language Q&A over the scan's findings.
 *
 * Posts to `POST /scans/{id}/ask`, which adjudicates the question against the
 * findings' evidence and remediation. Answering spends tokens (metered in the
 * AI cost panel), so it is on demand, not polled. The endpoint returns 402 for
 * a non-premium tenant and 502 when the AI runtime is unavailable; both surface
 * here as an inline message rather than failing the page.
 */
const SUGGESTIONS = [
  "What is the single most critical issue and why?",
  "Which findings should I fix first?",
  "Summarise the authorization weaknesses.",
];

interface Turn {
  question: string;
  answer: string;
}

export function AskPanel({ id }: { id: string }) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<number | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [collapsedLoaded, setCollapsedLoaded] = useState(false);
  const threadEndRef = useRef<HTMLDivElement | null>(null);

  const asking = pending !== null;

  useEffect(() => {
    const storageKey = "aidetector-ask-" + id + "-collapsed";
    try {
      const saved = window.localStorage.getItem(storageKey);
      if (saved === "true" || saved === "false") {
        setCollapsed(saved === "true");
      }
    } catch {
      // Storage can be unavailable in privacy-restricted browser contexts.
    } finally {
      setCollapsedLoaded(true);
    }
  }, [id]);

  useEffect(() => {
    if (!collapsedLoaded) return;

    try {
      window.localStorage.setItem(
        "aidetector-ask-" + id + "-collapsed",
        String(collapsed),
      );
    } catch {
      // Storage can be unavailable in privacy-restricted browser contexts.
    }
  }, [collapsed, collapsedLoaded, id]);

  // Keep the newest turn (or the thinking bubble) in view as the thread grows.
  useEffect(() => {
    if (asking || turns.length > 0) {
      threadEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [turns.length, asking]);

  async function ask(q: string) {
    const trimmed = q.trim();
    if (!trimmed || asking) return;
    setError(null);
    setPending(trimmed);
    setQuestion("");
    try {
      const res = await api.ask(id, trimmed);
      setTurns((prev) => [...prev, { question: trimmed, answer: res.answer }]);
    } catch (e) {
      // req() throws the API's `detail` string: "premium tier required" (402),
      // "AI unavailable" (502), else a bare status code.
      const msg = e instanceof Error ? e.message : String(e);
      setError(
        /premium/i.test(msg)
          ? "Ask-your-scan is a premium feature — this tenant is not on the premium tier."
          : /unavailable/i.test(msg)
            ? "The AI assistant is unavailable right now. Try again once the AI runtime is configured."
            : msg,
      );
      setQuestion(trimmed); // restore so the user can retry or edit
    } finally {
      setPending(null);
    }
  }

  async function copyAnswer(text: string, i: number) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(i);
      setTimeout(() => setCopied((c) => (c === i ? null : c)), 1500);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

  const empty = turns.length === 0 && !asking;

  return (
    <section className="panel ask-panel">
      <button
        type="button"
        className="ask-head"
        onClick={() => setCollapsed((c) => !c)}
        aria-expanded={!collapsed}
        aria-controls="ask-body"
      >
        <span className="ask-title">Ask your scan</span>
        <span className="premium-badge" title="Premium feature">
          Premium
        </span>
        {turns.length > 0 && (
          <span className="ask-count">
            {turns.length} question{turns.length === 1 ? "" : "s"}
          </span>
        )}
        <span className="ask-toggle">{collapsed ? "Show" : "Hide"}</span>
        <span
          className={`ask-chevron${collapsed ? " collapsed" : ""}`}
          aria-hidden="true"
        >
          ▾
        </span>
      </button>

      <div id="ask-body" hidden={collapsed}>
      <p className="muted-note">
        Ask a question about these findings — grounded only in what the scan
        found. Each answer spends AI tokens (see cost above).
      </p>

      {(turns.length > 0 || asking) && (
        <div className="ask-thread">
          {turns.map((t, i) => (
            <div className="ask-turn" key={i}>
              <div className="ask-q">
                <span className="you-tag">You</span>
                <p>{t.question}</p>
              </div>
              <div className="ask-answer">
                <span className="ai-tag">AI</span>
                <div className="ask-answer-body">{renderRich(t.answer)}</div>
                <button
                  type="button"
                  className="ask-copy"
                  onClick={() => void copyAnswer(t.answer, i)}
                  aria-label="Copy answer"
                  title="Copy answer"
                >
                  {copied === i ? "✓ Copied" : "Copy"}
                </button>
              </div>
            </div>
          ))}
          {asking && pending && (
            <div className="ask-turn">
              <div className="ask-q">
                <span className="you-tag">You</span>
                <p>{pending}</p>
              </div>
              <div className="ask-answer thinking">
                <span className="ai-tag">AI</span>
                <span className="ask-dots" aria-label="Thinking">
                  <i />
                  <i />
                  <i />
                </span>
              </div>
            </div>
          )}
          <div ref={threadEndRef} />
        </div>
      )}

      {error && <div className="ask-error">{error}</div>}

      <form
        className="ask-form"
        onSubmit={(e) => {
          e.preventDefault();
          void ask(question);
        }}
      >
        <div className="ask-input">
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder={
              empty
                ? "e.g. Which findings let an attacker read another tenant's data?"
                : "Ask a follow-up…"
            }
            rows={2}
            aria-label="Question about the scan"
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                void ask(question);
              }
            }}
          />
          <span className="ask-kbd">⌘/Ctrl + ⏎</span>
        </div>
        <button className="btn" type="submit" disabled={asking || !question.trim()}>
          {asking ? "Thinking…" : "Ask"}
        </button>
      </form>

      {empty && (
        <div className="ask-suggestions">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              type="button"
              className="chipbtn"
              disabled={asking}
              onClick={() => void ask(s)}
            >
              {s}
            </button>
          ))}
        </div>
      )}
      </div>
    </section>
  );
}
