"use client";

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type MouseEvent,
  type ReactNode,
} from "react";
import {
  api,
  type Budget,
  type CreatedNotificationEndpoint,
  type CreatedToken,
  type DomainProof,
  type DomainVerification,
  type NotificationDelivery,
  type NotificationEndpoint,
  type NotificationEvent,
  type NotificationSeverity,
  type PendingSignup,
  type Workspace,
  type WorkspaceAuditRow,
  type WorkspaceMember,
  type WorkspaceRole,
  type WorkspaceToken,
} from "@/lib/api";
import { useUrlState } from "@/lib/useUrlState";
import { usePageTitle } from "../components/usePageTitle";
import { CopyButton } from "../components/ui";

// Workspace settings, laid out the way a settings area is expected to read: a
// section list on the left, one section at a time on the right, every panel
// headed by what it is and the action it offers, and every empty state saying
// what to do next. The section lives in the URL (?section=members), so a link
// or a reload lands on it.

type SectionId =
  | "general"
  | "members"
  | "signups"
  | "tokens"
  | "limits"
  | "domains"
  | "notifications"
  | "audit";

interface SectionDef {
  id: SectionId;
  label: string;
  group: string;
  title: string;
  description: string;
  adminOnly: boolean;
}

const SECTIONS: SectionDef[] = [
  {
    id: "general",
    label: "General",
    group: "Workspace",
    title: "General",
    description: "The workspace you are signed in to, its plan and your role in it.",
    adminOnly: false,
  },
  {
    id: "members",
    label: "Members",
    group: "Workspace",
    title: "Members",
    description: "People who can see and act on this workspace's scans. A role decides what each of them may do.",
    adminOnly: false,
  },
  {
    id: "signups",
    label: "Pending sign-ups",
    group: "Workspace",
    title: "Pending sign-ups",
    description: "Requests for an account in this workspace. Approving one adds the person as a member with the role you choose.",
    adminOnly: true,
  },
  {
    id: "tokens",
    label: "API tokens",
    group: "Workspace",
    title: "API tokens",
    description: "Tokens for the CLI and CI. A token acts as the member it belongs to, with that member's role.",
    adminOnly: true,
  },
  {
    id: "domains",
    label: "Domains",
    group: "Workspace",
    title: "Domains",
    description:
      "Public hosts this workspace has proved it controls, so scans may target them. Private and lab targets need no proof.",
    adminOnly: true,
  },
  {
    id: "limits",
    label: "Spending & limits",
    group: "Usage",
    title: "Spending & run limits",
    description: "Cap what AI passes may spend and how many scans may run. A refused AI pass is skipped, never a failed scan.",
    adminOnly: true,
  },
  {
    id: "notifications",
    label: "Notifications",
    group: "Integrations",
    title: "Notifications",
    description: "Send scan and monitoring events to a signed webhook or a Slack channel.",
    adminOnly: true,
  },
  {
    id: "audit",
    label: "Audit log",
    group: "Security",
    title: "Audit log",
    description: "Who changed what in this workspace, and when. Credential values and secrets are never recorded.",
    adminOnly: true,
  },
];

const ROLES: { id: WorkspaceRole; label: string; detail: string }[] = [
  { id: "viewer", label: "Viewer", detail: "Reads scans, findings and reports." },
  { id: "analyst", label: "Analyst", detail: "Everything a viewer can, plus running scans, triaging findings and assigning work." },
  { id: "admin", label: "Admin", detail: "Everything an analyst can, plus managing members, tokens, limits and notifications." },
];

const EVENTS: { id: NotificationEvent; label: string; detail: string }[] = [
  { id: "finding.new", label: "New finding", detail: "A run found something the previous run did not." },
  { id: "run.failed", label: "Run failed", detail: "A scan run failed." },
  { id: "run.recovered", label: "Run recovered", detail: "A run completed after the previous one failed." },
  { id: "work.overdue", label: "Overdue task", detail: "An assigned finding passed its due date." },
  { id: "monitor.alert", label: "Monitoring alert", detail: "A traffic monitor raised an alert." },
  { id: "monitor.recovered", label: "Monitor recovered", detail: "A monitor's alert cleared." },
];
const EVENT_LABEL = new Map(EVENTS.map((event) => [event.id as string, event.label]));

const SEVERITIES: NotificationSeverity[] = ["info", "low", "medium", "high", "critical"];

function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

function roleLabel(role: WorkspaceRole): string {
  return ROLES.find((r) => r.id === role)?.label ?? role;
}

function absolute(iso: string | null): string {
  if (!iso) return "";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

function relative(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} d ago`;
  return date.toLocaleDateString();
}

/** A time cell: relative for scanning, absolute on hover and for assistive tech. */
function When({ iso }: { iso: string | null }) {
  if (!iso) return <span className="st-muted">—</span>;
  return (
    <time dateTime={iso} title={absolute(iso)}>
      {relative(iso)}
    </time>
  );
}

function usd(micros: number): string {
  const dollars = micros / 1_000_000;
  return dollars >= 1 || dollars === 0 ? `$${dollars.toFixed(2)}` : `$${dollars.toFixed(4)}`;
}

/** `monitoring.setup_updated` → "Monitoring · setup updated". */
function humanAction(action: string): string {
  const [area, ...rest] = action.split(".");
  const verb = rest.join(".").replaceAll("_", " ");
  const head = area ? area.charAt(0).toUpperCase() + area.slice(1) : action;
  return verb ? `${head} · ${verb}` : head;
}

function tokenStatus(token: WorkspaceToken): { label: string; tone: string } {
  if (token.revoked_at) return { label: "Revoked", tone: "muted" };
  if (token.expires_at && new Date(token.expires_at).getTime() < Date.now()) {
    return { label: "Expired", tone: "amber" };
  }
  return { label: "Active", tone: "ok" };
}

function deliveryTone(state: string): string {
  if (state === "delivered") return "ok";
  if (state === "failed" || state === "dead") return "red";
  if (state === "cancelled") return "muted";
  return "amber";
}

// ---- building blocks ---------------------------------------------------------

function Panel({
  title,
  actions,
  children,
  flush = false,
}: {
  title: string;
  actions?: ReactNode;
  children: ReactNode;
  /** The body is a table or list that reaches the panel's edges. */
  flush?: boolean;
}) {
  const id = useId();
  return (
    <section className="sp" aria-labelledby={id}>
      <header className="sp-head">
        <h2 id={id}>{title}</h2>
        {actions && <div className="sp-actions">{actions}</div>}
      </header>
      <div className={flush ? "sp-body flush" : "sp-body"}>{children}</div>
    </section>
  );
}

/** A label and its help on the left, the control on the right. */
function Field({
  label,
  help,
  children,
  htmlFor,
}: {
  label: string;
  help?: ReactNode;
  htmlFor?: string;
  children: ReactNode;
}) {
  const helpId = `${htmlFor ?? label}-help`;
  return (
    <div className="sp-field">
      <div className="sp-field-label">
        {htmlFor ? <label htmlFor={htmlFor}>{label}</label> : <span>{label}</span>}
        {help && (
          <p className="sp-help" id={helpId}>
            {help}
          </p>
        )}
      </div>
      <div className="sp-field-control">{children}</div>
    </div>
  );
}

function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="sp-empty">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

function Chip({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={`sp-chip ${tone}`}>{children}</span>;
}

/** A one-time secret: shown once, with a copy button, until dismissed. */
function Secret({
  title,
  value,
  onDismiss,
}: {
  title: string;
  value: string;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }
  return (
    <div className="sp-secret" role="status">
      <div>
        <strong>{title}</strong>
        <p>Copy it now. It will not be shown again.</p>
        <code>{value}</code>
      </div>
      <div className="sp-secret-actions">
        <button className="btn sm" type="button" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy"}
        </button>
        <button className="btn quiet sm" type="button" onClick={onDismiss}>
          Done
        </button>
      </div>
    </div>
  );
}

// ---- the page -------------------------------------------------------------------

export default function WorkspacePage() {
  const { get: getUrl, set: setUrl } = useUrlState();
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [signups, setSignups] = useState<PendingSignup[]>([]);
  const [tokens, setTokens] = useState<WorkspaceToken[]>([]);
  const [domains, setDomains] = useState<DomainVerification[]>([]);
  const [audit, setAudit] = useState<WorkspaceAuditRow[]>([]);
  const [notifications, setNotifications] = useState<NotificationEndpoint[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [budget, setBudget] = useState<Budget | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const admin = workspace?.role === "admin";
  // Until the role is known every section is listed, so the heading and the
  // highlighted link match the URL instead of flashing "General".
  const visibleSections = SECTIONS.filter((s) => !workspace || admin || !s.adminOnly);
  const requested = getUrl("section");
  const active =
    visibleSections.find((s) => s.id === requested) ?? visibleSections[0] ?? SECTIONS[0]!;
  usePageTitle(`Workspace · ${active.title}`);

  const load = useCallback(async () => {
    try {
      // Read everything first and set it together: setting the workspace
      // before the admin lists arrive rendered "No activity yet" (and other
      // empty states) for data that was still on its way.
      const current = await api.getWorkspace();
      const [nextMembers, admin] = await Promise.all([
        api.listMembers(),
        current.role === "admin"
          ? Promise.all([
              api.listSignups(),
              api.listTokens(),
              api.listAudit(),
              api.listNotifications(),
              api.listNotificationDeliveries(),
              api.getBudget(),
              api.listDomains(),
            ])
          : Promise.resolve(null),
      ]);
      setWorkspace(current);
      setMembers(nextMembers);
      if (admin) {
        const [
          nextSignups,
          nextTokens,
          nextAudit,
          nextNotifications,
          nextDeliveries,
          nextBudget,
          nextDomains,
        ] = admin;
        setSignups(nextSignups);
        setTokens(nextTokens);
        setAudit(nextAudit);
        setNotifications(nextNotifications);
        setDeliveries(nextDeliveries);
        setBudget(nextBudget);
        setDomains(nextDomains);
      }
      setLoadError(null);
    } catch (e) {
      setLoadError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function go(event: MouseEvent<HTMLAnchorElement>, id: SectionId) {
    // A real link (new tab, copy link) that switches in place on a plain click.
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    setError(null);
    setNotice(null);
    setUrl({ section: id === "general" ? null : id });
    // Move focus to the new section's heading, as a page change would.
    requestAnimationFrame(() => headingRef.current?.focus());
  }

  /** Run a mutation with one busy flag, one error banner and one notice. */
  const act = useCallback(
    async (work: () => Promise<void>, done?: string) => {
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        await work();
        await load();
        if (done) setNotice(done);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [load],
  );

  const groups = [...new Set(visibleSections.map((s) => s.group))];
  const counts: Partial<Record<SectionId, number>> = {
    members: members.length,
    signups: signups.length,
    tokens: tokens.filter((t) => !t.revoked_at).length,
    notifications: notifications.length,
  };

  return (
    <div className="wrap settings">
      <aside className="settings-side">
        <div className="settings-org">
          <span className="settings-avatar" aria-hidden="true">
            {(workspace?.name ?? "W").charAt(0).toUpperCase()}
          </span>
          <div>
            <strong>{workspace?.name ?? "Workspace"}</strong>
            <span>
              {workspace ? `${capitalize(workspace.plan)} plan · ${roleLabel(workspace.role)}` : "Loading…"}
            </span>
          </div>
        </div>
        <nav aria-label="Workspace settings" className="settings-nav">
          {groups.map((group) => (
            <div key={group} className="settings-nav-group">
              <p>{group}</p>
              <ul>
                {visibleSections
                  .filter((s) => s.group === group)
                  .map((s) => (
                    <li key={s.id}>
                      <a
                        href={s.id === "general" ? "/workspace" : `/workspace?section=${s.id}`}
                        aria-current={s.id === active.id ? "page" : undefined}
                        onClick={(e) => go(e, s.id)}
                      >
                        <span>{s.label}</span>
                        {counts[s.id] !== undefined && counts[s.id]! > 0 && (
                          <>
                            <span className="settings-count" aria-hidden="true">
                              {counts[s.id]}
                            </span>
                            <span className="sr-only">({counts[s.id]})</span>
                          </>
                        )}
                      </a>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      {/* The layout already provides <main>; this is the settings content region. */}
      <div className="settings-main" aria-busy={loading}>
        <header className="settings-header">
          <h1 ref={headingRef} tabIndex={-1}>
            {active.title}
          </h1>
          <p>{active.description}</p>
        </header>

        <div aria-live="polite" className="settings-messages">
          {notice && (
            <p className="sp-banner ok" role="status">
              {notice}
            </p>
          )}
        </div>
        {error && (
          <p className="sp-banner red" role="alert">
            {error}
          </p>
        )}
        {loadError && (
          <div className="sp-banner red" role="alert">
            <span>Could not load the workspace: {loadError}</span>
            <button className="btn quiet sm" type="button" onClick={() => void load()}>
              Retry
            </button>
          </div>
        )}

        {loading && !workspace ? (
          <Panel title="Loading">
            <p className="st-muted">Loading the workspace…</p>
          </Panel>
        ) : (
          workspace && (
            <>
              {active.id === "general" && <General workspace={workspace} />}
              {active.id === "members" && (
                <Members
                  members={members}
                  admin={admin}
                  busy={busy}
                  currentUser={workspace.user?.id ?? null}
                  act={act}
                />
              )}
              {active.id === "signups" && admin && (
                <PendingSignups signups={signups} busy={busy} act={act} />
              )}
              {active.id === "tokens" && admin && (
                <Tokens
                  tokens={tokens}
                  members={members}
                  busy={busy}
                  act={act}
                  onNeedMembers={(e) => go(e, "members")}
                />
              )}
              {active.id === "limits" && admin && budget && (
                <Limits budget={budget} busy={busy} act={act} />
              )}
              {active.id === "domains" && admin && (
                <Domains domains={domains} busy={busy} act={act} />
              )}
              {active.id === "notifications" && admin && (
                <Notifications
                  endpoints={notifications}
                  deliveries={deliveries}
                  busy={busy}
                  act={act}
                />
              )}
              {active.id === "audit" && admin && <Audit rows={audit} />}
            </>
          )
        )}
      </div>
    </div>
  );
}

type Act = (work: () => Promise<void>, done?: string) => Promise<void>;

// ---- General ---------------------------------------------------------------------

function General({ workspace }: { workspace: Workspace }) {
  return (
    <>
      <Panel title="Workspace">
        <Field label="Name">
          <span className="sp-value">{workspace.name}</span>
        </Field>
        <Field label="Slug" help="Scans, monitors and API keys are scoped to it.">
          <code className="sp-value">{workspace.tenant}</code>
        </Field>
        <Field label="Plan">
          <Chip tone={workspace.plan === "free" ? "muted" : "accent"}>{capitalize(workspace.plan)}</Chip>
        </Field>
        <Field label="Members">
          <span className="sp-value">{workspace.members}</span>
        </Field>
      </Panel>
      <Panel title="You">
        <Field label="Signed in as">
          <span className="sp-value">
            {workspace.user
              ? `${workspace.user.display_name} · ${workspace.user.email}`
              : "An operator API key (no member account)"}
          </span>
        </Field>
        <Field label="Role" help={ROLES.find((r) => r.id === workspace.role)?.detail}>
          <Chip tone="accent">{roleLabel(workspace.role)}</Chip>
        </Field>
      </Panel>
    </>
  );
}

// ---- Members --------------------------------------------------------------------

function Members({
  members,
  admin,
  busy,
  currentUser,
  act,
}: {
  members: WorkspaceMember[];
  admin: boolean;
  busy: boolean;
  currentUser: string | null;
  act: Act;
}) {
  const [adding, setAdding] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<WorkspaceRole>("analyst");
  const firstField = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (adding) firstField.current?.focus();
  }, [adding]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(async () => {
      await api.addMember({ email: email.trim(), display_name: name.trim(), role });
      setEmail("");
      setName("");
      setAdding(false);
    }, "Member added.");
  }

  const addButton = admin && !adding && (
    <button className="btn sm" type="button" onClick={() => setAdding(true)}>
      Add member
    </button>
  );

  return (
    <>
      {adding && (
        <Panel title="Add a member">
          <form onSubmit={submit}>
            <Field label="Email" htmlFor="member-email">
              <input
                id="member-email"
                ref={firstField}
                type="email"
                required
                autoComplete="off"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </Field>
            <Field label="Display name" htmlFor="member-name">
              <input
                id="member-name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="Role" htmlFor="member-role" help={ROLES.find((r) => r.id === role)?.detail}>
              <select
                id="member-role"
                aria-describedby="member-role-help"
                value={role}
                onChange={(e) => setRole(e.target.value as WorkspaceRole)}
              >
                {ROLES.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.label}
                  </option>
                ))}
              </select>
            </Field>
            <div className="sp-form-actions">
              <button className="btn quiet sm" type="button" onClick={() => setAdding(false)}>
                Cancel
              </button>
              <button className="btn sm" type="submit" disabled={busy}>
                Add member
              </button>
            </div>
          </form>
        </Panel>
      )}

      <Panel title={`Members · ${members.length}`} actions={addButton} flush>
        {members.length === 0 ? (
          <Empty
            title="No members yet"
            action={addButton}
          >
            {admin
              ? "Add the people who should see this workspace. Each member gets a role, and API tokens are issued to members."
              : "An admin adds the people who can use this workspace."}
          </Empty>
        ) : (
          <table className="settings-table">
            <thead>
              <tr>
                <th scope="col">Member</th>
                <th scope="col">Role</th>
                <th scope="col">Joined</th>
                {admin && (
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {members.map((member) => (
                <tr key={member.user_id}>
                  <td>
                    <strong>{member.display_name}</strong>
                    {member.user_id === currentUser && <Chip tone="muted">You</Chip>}
                    <span className="cell-sub">{member.email}</span>
                  </td>
                  <td>
                    {admin ? (
                      <select
                        aria-label={`Role for ${member.display_name}`}
                        value={member.role}
                        disabled={busy}
                        onChange={(e) =>
                          void act(
                            () => api.changeRole(member.user_id, e.target.value as WorkspaceRole).then(() => undefined),
                            `${member.display_name} is now ${roleLabel(e.target.value as WorkspaceRole)}.`,
                          )
                        }
                      >
                        {ROLES.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      roleLabel(member.role)
                    )}
                  </td>
                  <td>
                    <When iso={member.created_at} />
                  </td>
                  {admin && (
                    <td className="cell-actions">
                      <button
                        className="btn danger sm"
                        type="button"
                        disabled={busy}
                        aria-label={`Remove ${member.display_name}`}
                        onClick={() => {
                          if (!window.confirm(`Remove ${member.display_name} from this workspace?`)) return;
                          void act(
                            () => api.removeMember(member.user_id).then(() => undefined),
                            `${member.display_name} removed.`,
                          );
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Roles">
        <dl className="sp-roles">
          {ROLES.map((r) => (
            <div key={r.id}>
              <dt>{r.label}</dt>
              <dd>{r.detail}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </>
  );
}

// ---- Pending sign-ups -------------------------------------------------------------

function PendingSignups({
  signups,
  busy,
  act,
}: {
  signups: PendingSignup[];
  busy: boolean;
  act: Act;
}) {
  // The role each request will be approved with; analyst until the admin says otherwise.
  const [roles, setRoles] = useState<Record<string, WorkspaceRole>>({});
  const roleFor = (userId: string) => roles[userId] ?? "analyst";

  return (
    <Panel title={`Pending sign-ups · ${signups.length}`} flush>
      {signups.length === 0 ? (
        <Empty title="No pending requests." />
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th scope="col">Requested by</th>
              <th scope="col">Role</th>
              <th scope="col">Requested</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {signups.map((signup) => (
              <tr key={signup.user_id}>
                <td>
                  <strong>{signup.display_name}</strong>
                  <span className="cell-sub">{signup.email}</span>
                </td>
                <td>
                  <select
                    aria-label={`Role for ${signup.display_name}`}
                    value={roleFor(signup.user_id)}
                    disabled={busy}
                    onChange={(e) =>
                      setRoles((prev) => ({
                        ...prev,
                        [signup.user_id]: e.target.value as WorkspaceRole,
                      }))
                    }
                  >
                    {ROLES.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.label}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <When iso={signup.requested_at} />
                </td>
                <td className="cell-actions">
                  <button
                    className="btn sm"
                    type="button"
                    disabled={busy}
                    aria-label={`Approve ${signup.display_name}`}
                    onClick={() =>
                      void act(
                        () => api.approveSignup(signup.user_id, roleFor(signup.user_id)).then(() => undefined),
                        `${signup.display_name} approved.`,
                      )
                    }
                  >
                    Approve
                  </button>
                  <button
                    className="btn danger sm"
                    type="button"
                    disabled={busy}
                    aria-label={`Reject ${signup.display_name}`}
                    onClick={() =>
                      void act(
                        () => api.rejectSignup(signup.user_id).then(() => undefined),
                        `${signup.display_name}'s request rejected.`,
                      )
                    }
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

// ---- API tokens -------------------------------------------------------------------

function Tokens({
  tokens,
  members,
  busy,
  act,
  onNeedMembers,
}: {
  tokens: WorkspaceToken[];
  members: WorkspaceMember[];
  busy: boolean;
  act: Act;
  onNeedMembers: (event: MouseEvent<HTMLAnchorElement>) => void;
}) {
  const [creating, setCreating] = useState(false);
  const [user, setUser] = useState("");
  const [label, setLabel] = useState("");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const firstField = useRef<HTMLSelectElement>(null);
  const noMembers = members.length === 0;

  useEffect(() => {
    if (creating) firstField.current?.focus();
  }, [creating]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(async () => {
      setCreated(await api.createToken({ user_id: user, label: label.trim() }));
      setCreating(false);
      setLabel("");
    }, "Token created.");
  }

  const createButton = !creating && !noMembers && (
    <button
      className="btn sm"
      type="button"
      onClick={() => setCreating(true)}
    >
      Create token
    </button>
  );

  return (
    <>
      {noMembers && (
        <p className="sp-banner amber" id="tokens-need-members">
          A token belongs to a member, and this workspace has none yet.{" "}
          <a href="/workspace?section=members" onClick={onNeedMembers}>
            Add a member first
          </a>
          .
        </p>
      )}
      {created && (
        <Secret
          title={`Token “${created.label || created.prefix}” for ${created.display_name}`}
          value={created.token}
          onDismiss={() => setCreated(null)}
        />
      )}
      {creating && (
        <Panel title="Create a token">
          <form onSubmit={submit}>
            <Field label="Member" htmlFor="token-member" help="The token can do what this member's role allows.">
              <select
                id="token-member"
                ref={firstField}
                required
                aria-describedby="token-member-help"
                value={user}
                onChange={(e) => setUser(e.target.value)}
              >
                <option value="">Choose a member…</option>
                {members.map((m) => (
                  <option key={m.user_id} value={m.user_id}>
                    {m.display_name} · {roleLabel(m.role)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Label" htmlFor="token-label" help="What uses it, so you know which one to revoke — “ci”, “laptop”.">
              <input
                id="token-label"
                type="text"
                aria-describedby="token-label-help"
                placeholder="ci"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </Field>
            <div className="sp-form-actions">
              <button className="btn quiet sm" type="button" onClick={() => setCreating(false)}>
                Cancel
              </button>
              <button className="btn sm" type="submit" disabled={busy || !user}>
                Create token
              </button>
            </div>
          </form>
        </Panel>
      )}

      <Panel title="Tokens" actions={createButton} flush>
        {tokens.length === 0 ? (
          <Empty
            title="No tokens yet"
            action={
              noMembers ? (
                <a className="btn sm" href="/workspace?section=members" onClick={onNeedMembers}>
                  Go to Members
                </a>
              ) : (
                createButton
              )
            }
          >
            Create one for the CLI or a CI job. Set it as <code>AIDETECTOR_API_KEY</code>; it is never
            accepted as a command-line flag.
          </Empty>
        ) : (
          <table className="settings-table">
            <thead>
              <tr>
                <th scope="col">Token</th>
                <th scope="col">Member</th>
                <th scope="col">Status</th>
                <th scope="col">Created</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => {
                const status = tokenStatus(token);
                return (
                  <tr key={token.id}>
                    <td>
                      <strong>{token.label || "Untitled"}</strong>
                      <code className="cell-sub">
                        {token.prefix}…{token.last4}
                      </code>
                    </td>
                    <td>
                      {token.display_name}
                      <span className="cell-sub">{token.email}</span>
                    </td>
                    <td>
                      <Chip tone={status.tone}>{status.label}</Chip>
                    </td>
                    <td>
                      <When iso={token.created_at} />
                    </td>
                    <td>
                      <When iso={token.last_used_at} />
                    </td>
                    <td className="cell-actions">
                      {!token.revoked_at && (
                        <button
                          className="btn danger sm"
                          type="button"
                          disabled={busy}
                          aria-label={`Revoke token ${token.label || token.prefix}`}
                          onClick={() => {
                            if (!window.confirm(`Revoke ${token.label || token.prefix}…${token.last4}? Anything using it stops working.`)) return;
                            void act(() => api.revokeToken(token.id).then(() => undefined), "Token revoked.");
                          }}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}

// ---- Spending & limits ---------------------------------------------------------

function toInput(value: number | null, scale = 1): string {
  return value === null ? "" : String(value / scale);
}

function Limits({ budget, busy, act }: { budget: Budget; busy: boolean; act: Act }) {
  const [monthly, setMonthly] = useState(toInput(budget.ai_monthly_micros, 1_000_000));
  const [perScan, setPerScan] = useState(toInput(budget.ai_per_scan_micros, 1_000_000));
  const [active, setActive] = useState(toInput(budget.max_concurrent_runs));
  const [queued, setQueued] = useState(toInput(budget.max_queued_runs));
  const [perDay, setPerDay] = useState(toInput(budget.scans_per_day));

  const limit = budget.ai_monthly_micros;
  const used = limit ? Math.min(100, Math.round((budget.month_spent_micros / limit) * 100)) : null;

  function micros(value: string): number | null {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) && parsed >= 0 ? Math.round(parsed * 1_000_000) : null;
  }
  function count(value: string): number | null {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(async () => {
      await api.setBudget({
        ai_monthly_micros: micros(monthly),
        ai_per_scan_micros: micros(perScan),
        max_concurrent_runs: count(active),
        max_queued_runs: count(queued),
        scans_per_day: count(perDay),
      });
    }, "Spending and run limits saved.");
  }

  return (
    <>
      <div className="sp-stats" role="group" aria-label="This month">
        <div className="sp-stat">
          <span>AI spend this month</span>
          <strong>{usd(budget.month_spent_micros)}</strong>
          {used !== null ? (
            <>
              <div
                className={`sp-meter${used >= 90 ? " hot" : ""}`}
                role="meter"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={used}
                aria-label="Monthly AI budget used"
              >
                <span style={{ width: `${used}%` }} />
              </div>
              <small>
                {used}% of {usd(limit!)}
              </small>
            </>
          ) : (
            <small>No monthly cap</small>
          )}
        </div>
        <div className="sp-stat">
          <span>Remaining</span>
          <strong>
            {budget.month_remaining_micros === null ? "Unlimited" : usd(budget.month_remaining_micros)}
          </strong>
          <small>Live AI calls hold their worst case until they finish</small>
        </div>
        <div className="sp-stat">
          <span>Active runs</span>
          <strong>{budget.active_runs}</strong>
          <small>
            {budget.max_concurrent_runs === null ? "No cap" : `of ${budget.max_concurrent_runs} allowed`}
          </small>
        </div>
        <div className="sp-stat">
          <span>Queued runs</span>
          <strong>{budget.queued_runs}</strong>
          <small>{budget.max_queued_runs === null ? "No cap" : `of ${budget.max_queued_runs} allowed`}</small>
        </div>
      </div>

      <form onSubmit={submit}>
        <Panel title="AI budget">
          <Field
            label="Monthly budget (USD)"
            htmlFor="limit-monthly"
            help="Across every scan in the workspace. Empty means no cap; 0 turns AI passes off."
          >
            <input
              id="limit-monthly"
              type="number"
              inputMode="decimal"
              min="0"
              step="0.01"
              placeholder="No cap"
              aria-describedby="limit-monthly-help"
              value={monthly}
              onChange={(e) => setMonthly(e.target.value)}
            />
          </Field>
          <Field
            label="Per-scan budget (USD)"
            htmlFor="limit-scan"
            help="The most one scan's AI passes may spend, counted across its runs."
          >
            <input
              id="limit-scan"
              type="number"
              inputMode="decimal"
              min="0"
              step="0.01"
              placeholder="No cap"
              aria-describedby="limit-scan-help"
              value={perScan}
              onChange={(e) => setPerScan(e.target.value)}
            />
          </Field>
        </Panel>
        <Panel title="Run limits">
          <Field
            label="Active runs"
            htmlFor="limit-active"
            help="Queued and running together. A run past it is refused with “run limit reached”."
          >
            <input
              id="limit-active"
              type="number"
              inputMode="numeric"
              min="1"
              step="1"
              placeholder="No cap"
              aria-describedby="limit-active-help"
              value={active}
              onChange={(e) => setActive(e.target.value)}
            />
          </Field>
          <Field label="Queued runs" htmlFor="limit-queued" help="How many runs may wait for a worker.">
            <input
              id="limit-queued"
              type="number"
              inputMode="numeric"
              min="0"
              step="1"
              placeholder="No cap"
              aria-describedby="limit-queued-help"
              value={queued}
              onChange={(e) => setQueued(e.target.value)}
            />
          </Field>
          <Field
            label="Runs per day"
            htmlFor="limit-day"
            help="Every accepted run counts, scheduled and local ones included, from midnight UTC."
          >
            <input
              id="limit-day"
              type="number"
              inputMode="numeric"
              min="1"
              step="1"
              placeholder="No cap"
              aria-describedby="limit-day-help"
              value={perDay}
              onChange={(e) => setPerDay(e.target.value)}
            />
          </Field>
        </Panel>
        <div className="sp-savebar">
          <span>Leave a field empty for no cap.</span>
          <button className="btn sm" type="submit" disabled={busy}>
            Save limits
          </button>
        </div>
      </form>
    </>
  );
}

// ---- Domains --------------------------------------------------------------------

function Domains({
  domains,
  busy,
  act,
}: {
  domains: DomainVerification[];
  busy: boolean;
  act: Act;
}) {
  const [host, setHost] = useState("");
  const [checking, setChecking] = useState<string | null>(null);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(async () => {
      await api.addDomain(host.trim());
      setHost("");
    }, "Domain added — publish the two proofs shown on its card, then press Check now.");
  }

  // The outcome is shown on the card itself (status and the step that failed),
  // so a check posts no banner of its own.
  function check(domain: DomainVerification, url: string | null) {
    setChecking(domain.id);
    void act(async () => {
      await api.verifyDomain(domain.id, url);
    }).finally(() => setChecking(null));
  }

  function remove(domain: DomainVerification) {
    if (
      !window.confirm(
        `Remove ${domain.host} from this workspace? Scans of it are refused until it is proved again.`,
      )
    )
      return;
    void act(() => api.deleteDomain(domain.id).then(() => undefined), "Domain removed.");
  }

  return (
    <>
      <Panel title="Add a domain">
        <p className="sp-help">
          A target that resolves to a public address is scanned only after this workspace proves it
          controls it; private and lab targets need nothing. You publish two proofs — a DNS TXT
          record for the name and a small HTTP file for the machine that answers — and every scan
          re-checks both.
        </p>
        <form onSubmit={submit}>
          <Field label="Host" htmlFor="domain-host" help="A hostname, not a URL.">
            <input
              id="domain-host"
              type="text"
              required
              autoComplete="off"
              placeholder="api.example.com"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </Field>
          <div className="sp-form-actions">
            <button className="btn sm" type="submit" disabled={busy}>
              Add
            </button>
          </div>
        </form>
      </Panel>

      {domains.length === 0 ? (
        <Panel title="Domains · 0">
          <Empty title="No domains yet">
            Add the public host a scan should target. Until both proofs pass, a scan of it is
            refused; private and lab targets are unaffected.
          </Empty>
        </Panel>
      ) : (
        <section className="domain-list" aria-label={`Domains · ${domains.length}`}>
          {domains.map((domain) => (
            <DomainCard
              key={domain.id}
              domain={domain}
              busy={busy}
              checking={checking === domain.id}
              onCheck={(url) => check(domain, url)}
              onRemove={() => remove(domain)}
            />
          ))}
        </section>
      )}
    </>
  );
}

type ProofState = "passed" | "failed" | "unchecked";

function proofOf(
  domain: DomainVerification,
  proof: DomainProof["proof"],
): { state: ProofState; detail: string | null } {
  const found = (domain.last_checks ?? []).find((c) => c.proof === proof);
  if (found) return { state: found.ok ? "passed" : "failed", detail: found.detail };
  // A row checked before per-proof results were kept: verified means both passed.
  return { state: domain.verified_at ? "passed" : "unchecked", detail: null };
}

function DomainCard({
  domain,
  busy,
  checking,
  onCheck,
  onRemove,
}: {
  domain: DomainVerification;
  busy: boolean;
  checking: boolean;
  onCheck: (url: string | null) => void;
  onRemove: () => void;
}) {
  const [origin, setOrigin] = useState("");
  const verified = Boolean(domain.verified_at);
  const hasDns = domain.dns_record_name !== null;
  const dns = proofOf(domain, "dns");
  const http = proofOf(domain, "http");
  const proofs = hasDns ? [dns, http] : [http];
  const passed = proofs.filter((p) => p.state === "passed").length;
  const checked = Boolean(domain.last_checked_at);
  // An error with no per-proof result: the host was refused before either ran.
  const refused =
    !verified && (domain.last_checks ?? []).length === 0 ? domain.last_error : null;

  const status = verified
    ? { tone: "ok", label: "Verified" }
    : checked
      ? { tone: "red", label: "Not verified" }
      : { tone: "muted", label: "Not checked yet" };

  const summary = verified
    ? "Both proofs passed. Every scan checks them again, so leave the record and the file in place."
    : refused
      ? null
      : checked
        ? `${passed} of ${proofs.length} proofs passed. Fix the step marked below, then check again.`
        : "Publish the proofs below, then press Check now. DNS changes can take a few minutes to appear.";

  const steps = (
    <ol className="domain-steps">
      {hasDns && (
        <ProofStep
          title="Add a DNS TXT record"
          state={dns.state}
          detail={dns.detail}
        >
          <dl className="domain-kv">
            <dt>Type</dt>
            <dd>
              <code>TXT</code>
            </dd>
            <dt>Name</dt>
            <dd>
              <code>{domain.dns_record_name}</code>
              <CopyButton
                value={domain.dns_record_name ?? ""}
                label={`Copy the DNS record name for ${domain.host}`}
              />
            </dd>
            <dt>Value</dt>
            <dd>
              <code>{domain.dns_record_value}</code>
              <CopyButton
                value={domain.dns_record_value}
                label={`Copy the DNS record value for ${domain.host}`}
              />
            </dd>
          </dl>
          <p className="sp-help">
            If your DNS provider adds the domain to record names for you, enter only the part before{" "}
            <code>{domain.host}</code>.
          </p>
        </ProofStep>
      )}
      <ProofStep title="Serve the token over HTTP" state={http.state} detail={http.detail}>
        <dl className="domain-kv">
          <dt>URL</dt>
          <dd>
            <code>{domain.http_url}</code>
            <CopyButton value={domain.http_url} label={`Copy the token URL for ${domain.host}`} />
            <a
              className="domain-open"
              href={domain.http_url}
              target="_blank"
              rel="noopener noreferrer"
            >
              Open ↗
            </a>
          </dd>
          <dt>Body</dt>
          <dd>
            <code>{domain.token}</code>
            <CopyButton value={domain.token} label={`Copy the token for ${domain.host}`} />
          </dd>
        </dl>
        <p className="sp-help">
          Answer with status 200 and the token as plain text, nothing else. Redirects are not
          followed, so serve it on this origin directly.
        </p>
      </ProofStep>
    </ol>
  );

  return (
    <article className={`domain-card${verified ? " is-verified" : ""}`}>
      <header className="domain-head">
        <div className="domain-title">
          <strong>{domain.host}</strong>
          <Chip tone={status.tone}>{status.label}</Chip>
          {checked && (
            <span className="domain-meta">
              Last checked <When iso={domain.last_checked_at} />
            </span>
          )}
        </div>
        <div className="domain-actions">
          <button
            className={verified ? "btn quiet sm" : "btn sm"}
            type="button"
            disabled={busy}
            aria-label={`Check ${domain.host} now`}
            onClick={() => onCheck(null)}
          >
            {checking ? "Checking…" : verified ? "Check again" : "Check now"}
          </button>
          <button
            className="btn danger sm"
            type="button"
            disabled={busy}
            aria-label={`Remove ${domain.host}`}
            onClick={onRemove}
          >
            Remove
          </button>
        </div>
      </header>

      {summary && <p className="domain-summary">{summary}</p>}
      {refused && (
        <p className="domain-summary is-error" role="alert">
          {refused}
        </p>
      )}

      {verified ? (
        <details className="domain-more">
          <summary>Show the published proofs</summary>
          {steps}
        </details>
      ) : (
        steps
      )}

      <details className="domain-more">
        <summary>Target isn&rsquo;t on https://{domain.host}?</summary>
        <p className="sp-help">
          A scan fetches the token from its own target&rsquo;s origin. If that is plain http or
          another port, check against it here.
        </p>
        <form
          className="domain-origin"
          onSubmit={(e) => {
            e.preventDefault();
            onCheck(origin.trim() || null);
          }}
        >
          <input
            className="sp-search"
            type="url"
            aria-label={`Origin to check for ${domain.host}`}
            placeholder={`http://${domain.host}:8080`}
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
          />
          <button className="btn quiet sm" type="submit" disabled={busy || !origin.trim()}>
            Check this origin
          </button>
        </form>
      </details>
    </article>
  );
}

const PROOF_MARK: Record<ProofState, { mark: string; label: string }> = {
  passed: { mark: "✓", label: "Passed" },
  failed: { mark: "✕", label: "Failed" },
  unchecked: { mark: "", label: "Not checked" },
};

function ProofStep({
  title,
  state,
  detail,
  children,
}: {
  title: string;
  state: ProofState;
  detail: string | null;
  children: ReactNode;
}) {
  const { mark, label } = PROOF_MARK[state];
  return (
    <li className={`domain-step is-${state}`}>
      <span className="domain-step-mark" aria-hidden="true">
        {mark}
      </span>
      <div className="domain-step-body">
        <div className="domain-step-head">
          <strong>{title}</strong>
          <span className="domain-step-state">{label}</span>
        </div>
        {state === "failed" && detail && (
          <p className="domain-step-error" role="alert">
            {detail}
          </p>
        )}
        {children}
      </div>
    </li>
  );
}

// ---- Notifications --------------------------------------------------------------

function Notifications({
  endpoints,
  deliveries,
  busy,
  act,
}: {
  endpoints: NotificationEndpoint[];
  deliveries: NotificationDelivery[];
  busy: boolean;
  act: Act;
}) {
  const [adding, setAdding] = useState(false);
  const [kind, setKind] = useState<"webhook" | "slack">("webhook");
  const [destination, setDestination] = useState("");
  const [events, setEvents] = useState<NotificationEvent[]>([
    "finding.new",
    "run.failed",
    "run.recovered",
    "work.overdue",
  ]);
  const [severity, setSeverity] = useState<NotificationSeverity>("medium");
  const [created, setCreated] = useState<CreatedNotificationEndpoint | null>(null);
  const firstField = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    if (adding) firstField.current?.focus();
  }, [adding]);

  function toggle(event: NotificationEvent) {
    setEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(async () => {
      const endpoint = await api.createNotification({
        kind,
        destination: destination.trim(),
        events,
        min_severity: severity,
      });
      setCreated(endpoint);
      setDestination("");
      setAdding(false);
    }, "Endpoint added.");
  }

  const addButton = !adding && (
    <button className="btn sm" type="button" onClick={() => setAdding(true)}>
      Add endpoint
    </button>
  );

  return (
    <>
      {created?.signing_secret && (
        <Secret
          title="Webhook signing secret"
          value={created.signing_secret}
          onDismiss={() => setCreated(null)}
        />
      )}
      {adding && (
        <Panel title="Add an endpoint">
          <form onSubmit={submit}>
            <Field label="Destination" htmlFor="notify-kind">
              <select
                id="notify-kind"
                ref={firstField}
                value={kind}
                onChange={(e) => setKind(e.target.value as "webhook" | "slack")}
              >
                <option value="webhook">Signed webhook</option>
                <option value="slack">Slack incoming webhook</option>
              </select>
            </Field>
            <Field
              label={kind === "slack" ? "Slack webhook URL" : "Webhook URL"}
              htmlFor="notify-url"
              help={
                kind === "slack"
                  ? "From Slack's Incoming Webhooks app. Stored encrypted; only its host is shown back."
                  : "Each delivery is signed; the signing secret is shown once after you add it."
              }
            >
              <input
                id="notify-url"
                type="url"
                required
                placeholder="https://"
                aria-describedby="notify-url-help"
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
              />
            </Field>
            <Field
              label="Minimum severity"
              htmlFor="notify-severity"
              help="New-finding events below it are not sent. Other events always are."
            >
              <select
                id="notify-severity"
                aria-describedby="notify-severity-help"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as NotificationSeverity)}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </Field>
            <fieldset className="sp-field sp-fieldset">
              <legend className="sp-field-label">
                <span>Events</span>
                <span className="sp-help">Choose at least one.</span>
              </legend>
              <div className="sp-field-control sp-checks">
                {EVENTS.map((e) => (
                  <label key={e.id} className="sp-check">
                    <input type="checkbox" checked={events.includes(e.id)} onChange={() => toggle(e.id)} />
                    <span>
                      <strong>{e.label}</strong>
                      <small>{e.detail}</small>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="sp-form-actions">
              <button className="btn quiet sm" type="button" onClick={() => setAdding(false)}>
                Cancel
              </button>
              <button className="btn sm" type="submit" disabled={busy || events.length === 0}>
                Add endpoint
              </button>
            </div>
          </form>
        </Panel>
      )}

      <Panel title="Endpoints" actions={addButton} flush>
        {endpoints.length === 0 ? (
          <Empty title="No endpoints yet" action={addButton}>
            Point new findings, failed runs and monitoring alerts at a webhook or a Slack channel.
            Delivery is retried, and an unchanged run state is not sent twice.
          </Empty>
        ) : (
          <table className="settings-table">
            <thead>
              <tr>
                <th scope="col">Endpoint</th>
                <th scope="col">Events</th>
                <th scope="col">Min severity</th>
                <th scope="col">Status</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint) => (
                <tr key={endpoint.id}>
                  <td>
                    <strong>{endpoint.kind === "slack" ? "Slack" : "Webhook"}</strong>
                    <span className="cell-sub">{endpoint.destination_hint}</span>
                  </td>
                  <td className="cell-wrap">
                    {endpoint.events.map((e) => (
                      <Chip key={e} tone="muted">
                        {EVENT_LABEL.get(e) ?? e}
                      </Chip>
                    ))}
                  </td>
                  <td>{capitalize(endpoint.min_severity)}</td>
                  <td>
                    <Chip tone={endpoint.active ? "ok" : "muted"}>
                      {endpoint.active ? "Active" : "Paused"}
                    </Chip>
                  </td>
                  <td className="cell-actions">
                    <button
                      className="btn quiet sm"
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void act(
                          () => api.testNotification(endpoint.id).then(() => undefined),
                          "Test delivery queued.",
                        )
                      }
                    >
                      Send test
                    </button>
                    <button
                      className="btn danger sm"
                      type="button"
                      disabled={busy}
                      aria-label={`Delete the ${endpoint.kind} endpoint at ${endpoint.destination_hint}`}
                      onClick={() => {
                        if (!window.confirm(`Delete the ${endpoint.kind} endpoint at ${endpoint.destination_hint}?`)) return;
                        void act(
                          () => api.deleteNotification(endpoint.id).then(() => undefined),
                          "Endpoint deleted.",
                        );
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Recent deliveries" flush>
        {deliveries.length === 0 ? (
          <Empty title="Nothing delivered yet">
            Deliveries appear here as events fire. “Send test” on an endpoint makes one now.
          </Empty>
        ) : (
          <table className="settings-table">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Event</th>
                <th scope="col">State</th>
                <th scope="col" className="num">
                  Attempts
                </th>
                <th scope="col">Last error</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.slice(0, 20).map((delivery) => (
                <tr key={delivery.id}>
                  <td>
                    <When iso={delivery.created_at} />
                  </td>
                  <td>{EVENT_LABEL.get(delivery.event_type) ?? delivery.event_type}</td>
                  <td>
                    <Chip tone={deliveryTone(delivery.state)}>{capitalize(delivery.state)}</Chip>
                  </td>
                  <td className="num">{delivery.attempts}</td>
                  <td className="cell-wrap">{delivery.last_error ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}

// ---- Audit log -----------------------------------------------------------------

function Audit({ rows }: { rows: WorkspaceAuditRow[] }) {
  const [filter, setFilter] = useState("");
  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? rows.filter(
        (row) =>
          row.action.toLowerCase().includes(needle) ||
          (row.actor?.display_name ?? "operator key").toLowerCase().includes(needle) ||
          row.object_type.toLowerCase().includes(needle),
      )
    : rows;
  return (
    <Panel
      title="Events"
      flush
      actions={
        rows.length > 0 && (
          <input
            type="search"
            className="sp-search"
            aria-label="Filter the audit log"
            placeholder="Filter events"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        )
      }
    >
      {rows.length === 0 ? (
        <Empty title="No activity yet">
          Membership, token, limit, notification and monitoring changes are recorded here as they
          happen.
        </Empty>
      ) : shown.length === 0 ? (
        <Empty title="Nothing matches that filter" />
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Who</th>
              <th scope="col">Action</th>
              <th scope="col">Object</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <tr key={row.id}>
                <td>
                  <When iso={row.created_at} />
                </td>
                <td>{row.actor?.display_name ?? <span className="st-muted">Operator key</span>}</td>
                <td>{humanAction(row.action)}</td>
                <td>
                  {row.object_type.replaceAll("_", " ")}
                  <code className="cell-sub" title={row.object_id}>
                    {row.object_id.slice(0, 8)}
                  </code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
