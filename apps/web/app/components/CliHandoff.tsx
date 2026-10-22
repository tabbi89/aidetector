"use client";

import Link from "next/link";
import { useId, useState } from "react";
import type { Credential } from "@/lib/api";
import { useConnection } from "@/lib/connection";
import { CopyButton } from "./ui";

/** A YAML scalar that stays a string and needs no quoting where possible. */
function yamlString(value: string): string {
  const safe = /^[A-Za-z0-9._@/:+-]+$/.test(value) &&
    !/^(true|false|null|~|[-+]?\d+(\.\d+)?)$/i.test(value);
  return safe ? value : JSON.stringify(value);
}

/** One environment variable per identity; never the secret itself. */
function secretEnv(cred: Credential, used: Set<string>): string {
  const base =
    (cred.role || cred.name || "identity")
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "") || "IDENTITY";
  let name = `${base}_SECRET`;
  let n = 2;
  while (used.has(name)) {
    name = `${base}_${n}_SECRET`;
    n += 1;
  }
  used.add(name);
  return name;
}

/**
 * The CLI supports local networks, source and CI: two forms of the same handoff
 * — reuse the scan this wizard configured, or write a committed project file.
 * The project file never holds a secret; it names environment variables, which
 * is also why the generated file has no `authorized` key.
 */
export function CliHandoff({
  scanId,
  target,
  credentials,
}: {
  scanId: string;
  target: string;
  credentials: Credential[];
}) {
  const [tab, setTab] = useState<"scan" | "project">("scan");
  const baseId = useId();
  // The active connection, not the build-time default: a handoff copied after
  // pointing the tab at another server must run against that server.
  const { serverUrl } = useConnection();

  const runCommand =
    `RUNPENTESTS_SERVER=${serverUrl} RUNPENTESTS_API_KEY=<your-api-key> ` +
    `runpentests run ${scanId} --authorized --fail-on high --verified-only`;

  // The CLI requires unique identity *names*, not unique roles: two profiles
  // may both be "admin" and still be legitimate (one basic, one bearer).
  const identities: Credential[] = [];
  const seenNames = new Set<string>();
  for (const cred of credentials) {
    const name = cred.name || cred.role;
    if (seenNames.has(name)) continue;
    seenNames.add(name);
    identities.push(cred);
  }

  const usedEnv = new Set<string>();
  const identityLines = identities.flatMap((cred) => {
    const lines = [
      `  - name: ${yamlString(cred.name || cred.role)}`,
      `    role: ${yamlString(cred.role || cred.name)}`,
      `    auth: ${cred.auth_type}`,
    ];
    if (
      (cred.auth_type === "header" ||
        cred.auth_type === "api_key" ||
        cred.auth_type === "query" ||
        cred.auth_type === "cookie") &&
      cred.header_name
    ) {
      lines.push(`    header: ${yamlString(cred.header_name)}`);
    }
    if (cred.privilege != null) lines.push(`    rank: ${cred.privilege}`);
    if (cred.tenant) lines.push(`    tenant: ${yamlString(cred.tenant)}`);
    if (cred.auth_type !== "none") lines.push(`    secret_env: ${secretEnv(cred, usedEnv)}`);
    return lines;
  });

  const projectFile = [
    "# runpentests.yml — project file for this scan.",
    "# Committed files never hold secrets: each identity names the environment",
    "# variable that holds its secret. There is no `authorized` key — consent is",
    "# answered by the command that runs the scan.",
    `target: ${yamlString(target)}`,
    `scan: ${yamlString(scanId)}`,
    "rps: 10",
    "",
    "# Optional:",
    "# spec: ./openapi.yaml",
    "# source: .",
    "# checks: [bola, bfla]",
    "# passes: [fuzz]",
    "# fail_on: high",
    "# verified_only: true",
    "# new_only: false",
    "",
    ...(identityLines.length > 0
      ? ["identities:", ...identityLines]
      : ["# identities: one per credential role, with a secret_env for each."]),
  ].join("\n");

  const projectCommand =
    `RUNPENTESTS_SERVER=${serverUrl} RUNPENTESTS_API_KEY=<your-api-key> ` +
    `runpentests ${target} --config ./runpentests.yml --authorized`;

  return (
    <section className="cli-handoff" aria-labelledby={`${baseId}-title`}>
      <h3 className="cli-title" id={`${baseId}-title`}>
        Continue from the CLI
      </h3>
      <p className="cli-intro">
        Use the CLI for local network access, source context or CI. Both forms
        reuse this scan&apos;s target, scope and identities. Local CLI runs are
        available on Free; running from the web requires Premium.{" "}
        <Link href="/cli">CLI guide →</Link>
      </p>

      <div className="cli-tabs" role="tablist" aria-label="CLI handoff">
        <button
          type="button"
          role="tab"
          id={`${baseId}-scan-tab`}
          aria-selected={tab === "scan"}
          aria-controls={`${baseId}-scan`}
          className="cli-tab"
          onClick={() => setTab("scan")}
        >
          Run this scan
        </button>
        <button
          type="button"
          role="tab"
          id={`${baseId}-project-tab`}
          aria-selected={tab === "project"}
          aria-controls={`${baseId}-project`}
          className="cli-tab"
          onClick={() => setTab("project")}
        >
          Project file
        </button>
      </div>

      {tab === "scan" ? (
        <div
          role="tabpanel"
          id={`${baseId}-scan`}
          aria-labelledby={`${baseId}-scan-tab`}
          className="cli-panel"
        >
          <div className="cli-command">
            <pre className="shell">{runCommand}</pre>
            <CopyButton value={runCommand} label="Copy run command" />
          </div>
          <p className="cli-note">
            <code>RUNPENTESTS_SERVER</code> is this deployment&apos;s API; the key
            comes from <code>RUNPENTESTS_API_KEY</code> or a prior{" "}
            <code>runpentests login</code>. The run sends its traffic from your
            machine (Docker and the runner image needed), waits for the
            service&apos;s analysis, and exits non-zero on findings at or above{" "}
            <code>high</code>.
          </p>
        </div>
      ) : (
        <div
          role="tabpanel"
          id={`${baseId}-project`}
          aria-labelledby={`${baseId}-project-tab`}
          className="cli-panel"
        >
          <div className="cli-command">
            <pre className="shell">{projectFile}</pre>
            <CopyButton value={projectFile} label="Copy project file" />
          </div>
          <div className="cli-command">
            <pre className="shell">{projectCommand}</pre>
            <CopyButton value={projectCommand} label="Copy project command" />
          </div>
          <p className="cli-note">
            The project file never holds secrets — it names environment
            variables. The target form always waits for the run.
          </p>
        </div>
      )}
    </section>
  );
}
