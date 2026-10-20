"use client";

import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import { api } from "@/lib/api";
import { useConnection, type ConnectionStatus } from "@/lib/connection";

type Mode = "signin" | "signup";

/** Mirrors the server's password rule, so the browser can say so first. */
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 256;

const COPY: Record<Mode, { title: string; lead: string; submit: string; busy: string }> = {
  signin: {
    title: "Sign in to runpentests",
    lead: "Use the email and password for your workspace.",
    submit: "Sign in",
    busy: "Signing in…",
  },
  signup: {
    title: "Request access",
    lead: "An admin reviews every request before the account can sign in.",
    submit: "Request access",
    busy: "Sending request…",
  },
};

/**
 * Email and password access to the workspace. A signed-in session is just an
 * API token: `signIn` hands it to the connection layer, which keeps it in this
 * tab. The token itself is never rendered.
 *
 * Rendered by `/login` and by `AuthGate` in place of any page the tab may not
 * see yet, so signing in from a deep link shows that page without a redirect.
 * One form, two modes: the switch sits under the form rather than as a second
 * "Sign in" button above it.
 */
export function SignInPanel({ onSignedIn }: { onSignedIn?: () => void }) {
  const { signIn, error: connectionError, status, serverUrl, refresh } = useConnection();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  // Sign-up errors are this form's own; sign-in errors come from the connection
  // (`error`), which `signIn` fills with the server's detail.
  const [signUpError, setSignUpError] = useState<string | null>(null);
  const [signInFailed, setSignInFailed] = useState(false);
  const [sent, setSent] = useState(false);
  const firstField = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const copy = COPY[mode];

  // The first empty field takes focus when the form appears or changes mode.
  useEffect(() => {
    if (!sent) firstField.current?.focus();
  }, [mode, sent]);

  function switchMode(next: Mode) {
    setMode(next);
    setSignUpError(null);
    setSignInFailed(false);
    setSent(false);
    setPassword("");
  }

  function edited() {
    // An error answers the last attempt; typing starts the next one.
    setSignUpError(null);
    setSignInFailed(false);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    edited();
    if (mode === "signup") {
      try {
        await api.signUp({
          email: email.trim(),
          display_name: displayName.trim(),
          password,
        });
        setPassword("");
        setSent(true);
      } catch (e) {
        setSignUpError((e as Error).message);
      } finally {
        setBusy(false);
      }
      return;
    }
    const ok = await signIn({ email: email.trim(), password });
    setBusy(false);
    if (ok) {
      onSignedIn?.();
      return;
    }
    setSignInFailed(true);
  }

  const error = mode === "signin" && signInFailed ? connectionError : signUpError;

  return (
    <div className="wrap auth">
      <section className="auth-card" aria-labelledby={titleId}>
        {sent ? (
          <RequestSent
            titleId={titleId}
            email={email.trim()}
            onBack={() => switchMode("signin")}
          />
        ) : (
          <>
            <header className="auth-head">
              <h1 id={titleId}>{copy.title}</h1>
              <p>{copy.lead}</p>
            </header>

            <ServerState status={status} serverUrl={serverUrl} retry={() => void refresh()} />

            <form className="auth-form" onSubmit={submit}>
              {mode === "signup" && (
                <label className="field">
                  <span>Full name</span>
                  <input
                    ref={firstField}
                    type="text"
                    name="display_name"
                    autoComplete="name"
                    placeholder="Ada Lovelace"
                    required
                    maxLength={120}
                    value={displayName}
                    onChange={(e) => {
                      setDisplayName(e.target.value);
                      edited();
                    }}
                  />
                </label>
              )}

              <label className="field">
                <span>Email</span>
                <input
                  ref={mode === "signin" ? firstField : undefined}
                  type="email"
                  name="email"
                  autoComplete={mode === "signin" ? "username" : "email"}
                  placeholder="you@company.com"
                  inputMode="email"
                  spellCheck={false}
                  required
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    edited();
                  }}
                />
              </label>

              <PasswordField
                mode={mode}
                value={password}
                onChange={(value) => {
                  setPassword(value);
                  edited();
                }}
              />

              {error && (
                <p className="banner error auth-error" role="alert">
                  {error}
                </p>
              )}

              <button className="btn auth-submit" type="submit" disabled={busy}>
                {busy ? copy.busy : copy.submit}
              </button>
            </form>

            <footer className="auth-foot">
              {mode === "signin" ? (
                <>
                  <p>
                    New here?{" "}
                    <button className="auth-link" type="button" onClick={() => switchMode("signup")}>
                      Request access
                    </button>
                  </p>
                  <p className="auth-help">
                    Forgot your password? Ask your workspace admin to reset it.
                  </p>
                </>
              ) : (
                <p>
                  Already approved?{" "}
                  <button className="auth-link" type="button" onClick={() => switchMode("signin")}>
                    Sign in
                  </button>
                </p>
              )}
            </footer>
          </>
        )}
      </section>
    </div>
  );
}

/**
 * Password with a show/hide toggle and a Caps Lock warning; on sign-up, the
 * length rule is a live check rather than an error after submitting.
 */
function PasswordField({
  mode,
  value,
  onChange,
}: {
  mode: Mode;
  value: string;
  onChange: (value: string) => void;
}) {
  const [visible, setVisible] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const inputId = useId();
  const hintId = useId();
  const signup = mode === "signup";
  const longEnough = value.length >= MIN_PASSWORD;

  function readCaps(event: KeyboardEvent<HTMLInputElement>) {
    setCapsLock(event.getModifierState?.("CapsLock") ?? false);
  }

  return (
    <div className="field auth-password">
      <label htmlFor={inputId}>Password</label>
      <div className="auth-password-row">
        <input
          id={inputId}
          type={visible ? "text" : "password"}
          name="password"
          autoComplete={signup ? "new-password" : "current-password"}
          required
          minLength={signup ? MIN_PASSWORD : undefined}
          maxLength={MAX_PASSWORD}
          aria-describedby={signup || capsLock ? hintId : undefined}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={readCaps}
          onKeyUp={readCaps}
          onBlur={() => setCapsLock(false)}
        />
        <button
          className="auth-reveal"
          type="button"
          aria-controls={inputId}
          aria-pressed={visible}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </div>
      {(signup || capsLock) && (
        <p id={hintId} className="auth-hint">
          {signup && (
            <span className={longEnough ? "auth-rule met" : "auth-rule"}>
              <span aria-hidden="true">{longEnough ? "✓" : "•"}</span> At least {MIN_PASSWORD} characters
            </span>
          )}
          {capsLock && <span className="auth-caps">Caps Lock is on</span>}
        </p>
      )}
    </div>
  );
}

function RequestSent({
  titleId,
  email,
  onBack,
}: {
  titleId: string;
  email: string;
  onBack: () => void;
}) {
  return (
    <div className="auth-sent" role="status">
      <span className="auth-sent-mark" aria-hidden="true">✓</span>
      <h1 id={titleId}>Request sent</h1>
      <p>
        An admin has to approve <strong>{email}</strong> before it can sign in. Once they do,
        sign in with the password you just chose.
      </p>
      <button className="btn quiet auth-submit" type="button" onClick={onBack}>
        Back to sign in
      </button>
    </div>
  );
}

/**
 * What the server's state means for signing in. An open server answers anyone,
 * which only happens while no admin has a password — so it is a setup step,
 * not a reason to let the tab in.
 */
function ServerState({
  status,
  serverUrl,
  retry,
}: {
  status: ConnectionStatus;
  serverUrl: string;
  retry: () => void;
}) {
  if (status === "open") {
    return (
      <div className="banner info auth-setup" role="status">
        <p>This server has no admin yet. Create one from a shell, then sign in:</p>
        <pre className="auth-cmd">make admin email=you@example.com</pre>
      </div>
    );
  }
  if (status === "rejected") {
    return (
      <p className="banner info" role="status">
        Your session ended. Sign in again.
      </p>
    );
  }
  if (status === "unreachable") {
    return (
      <p className="banner error" role="alert">
        Nothing answered at {serverUrl}. Check that the API is running.{" "}
        <button className="btn quiet sm" type="button" onClick={retry}>
          Retry
        </button>
      </p>
    );
  }
  return null;
}
