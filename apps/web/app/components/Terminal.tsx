/**
 * A terminal window for documentation: chrome, a prompt, and colourised output.
 *
 * Static and presentational — the /cli guide renders captured CLI sessions
 * with it. A line starting with "$ " is a command, "# " a comment; any other
 * line is output. With `highlight`, output picks up the colours the findings
 * views use: severities, the evidence tier, and a diff's +/- markers.
 */

export type Tone = "ok" | "warn" | "err" | "dim" | "accent";
export type TermLine = string | { text: string; tone: Tone };

const TOKEN =
  /\b(critical|high|medium|low|info|verified|heuristic|error:|warning:)(?=\s|$)/g;

const TOKEN_CLASS: Record<string, string> = {
  critical: "t-crit",
  high: "t-high",
  medium: "t-med",
  low: "t-low",
  info: "t-dim",
  verified: "t-ok",
  heuristic: "t-warn",
  "error:": "t-err",
  "warning:": "t-warn",
};

function colourise(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(TOKEN)) {
    const at = m.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    out.push(
      <span key={at} className={TOKEN_CLASS[m[1]]}>
        {m[1]}
      </span>,
    );
    last = at + m[1].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function renderLine(line: TermLine, highlight: boolean): React.ReactNode {
  if (typeof line !== "string") {
    return <span className={`t-${line.tone}`}>{line.text}</span>;
  }
  if (line.startsWith("$ ")) {
    return (
      <>
        <span className="t-prompt" aria-hidden="true">
          ${" "}
        </span>
        <span className="t-cmd">{line.slice(2)}</span>
      </>
    );
  }
  if (line.startsWith("# ")) return <span className="t-dim">{line}</span>;
  if (!highlight) return line;
  if (/^\s*\+ /.test(line)) return <span className="t-err">{line}</span>;
  if (/^\s*- /.test(line)) return <span className="t-ok">{line}</span>;
  return colourise(line);
}

export function Terminal({
  title = "zsh",
  lines,
  highlight = false,
  caption,
}: {
  title?: string;
  lines: TermLine[];
  highlight?: boolean;
  caption?: React.ReactNode;
}) {
  return (
    <figure className="term">
      <div className="term-bar" aria-hidden="true">
        <i />
        <i />
        <i />
        <span>{title}</span>
      </div>
      <pre className="term-body">
        <code>
          {lines.map((line, i) => (
            <span className="term-line" key={i}>
              {renderLine(line, highlight)}
              {"\n"}
            </span>
          ))}
        </code>
      </pre>
      {caption ? <figcaption>{caption}</figcaption> : null}
    </figure>
  );
}
