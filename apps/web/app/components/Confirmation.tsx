"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";

type Confirmation = {
  title: string;
  description: string;
  actionLabel: string;
  cancelLabel?: string;
  intent?: "danger" | "warning";
  confirmText?: string;
  action: () => Promise<unknown> | void;
};
type ConfirmAction = (options: Confirmation) => Promise<boolean>;
const Context = createContext<ConfirmAction | null>(null);

export function useConfirmation() {
  const confirmAction = useContext(Context);
  if (!confirmAction) throw new Error("ConfirmationProvider is required");
  return confirmAction;
}

/** Native modal mechanics, app-owned copy, feedback and asynchronous action. */
export function ConfirmationProvider({ children }: { children: ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const pending = useRef<{
    options: Confirmation;
    resolve: (value: boolean) => void;
    trigger: HTMLElement | null;
  } | null>(null);
  const executing = useRef(false);
  const [options, setOptions] = useState<Confirmation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [text, setText] = useState("");
  const title = useId(),
    description = useId();

  const finish = useCallback((accepted: boolean) => {
    const request = pending.current;
    pending.current = null;
    executing.current = false;
    dialog.current?.close();
    setOptions(null);
    setBusy(false);
    request?.resolve(accepted);
    requestAnimationFrame(() => {
      if (request?.trigger?.isConnected) request.trigger.focus();
      else document.getElementById("main")?.focus();
    });
  }, []);

  const confirmAction = useCallback<ConfirmAction>((next) => {
    if (pending.current) return Promise.resolve(false);
    return new Promise((resolve) => {
      pending.current = {
        options: next,
        resolve,
        trigger:
          document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null,
      };
      setError("");
      setText("");
      setOptions(next);
    });
  }, []);

  useEffect(() => {
    if (!options || !dialog.current || dialog.current.open) return;
    dialog.current.showModal();
    cancel.current?.focus();
  }, [options]);

  useEffect(
    () => () => {
      pending.current?.resolve(false);
    },
    [],
  );

  async function execute() {
    const request = pending.current;
    if (
      !request ||
      executing.current ||
      (request.options.confirmText &&
        text.trim() !== request.options.confirmText)
    )
      return;
    executing.current = true;
    setBusy(true);
    setError("");
    try {
      await request.options.action();
      finish(true);
    } catch (cause) {
      executing.current = false;
      setBusy(false);
      setError(
        cause instanceof Error
          ? cause.message
          : "The action could not be completed. Try again.",
      );
    }
  }

  return (
    <Context.Provider value={confirmAction}>
      {children}
      <dialog
        ref={dialog}
        className="confirmation"
        aria-labelledby={title}
        aria-describedby={description}
        onKeyDown={(event) => {
          if (event.key !== "Tab") return;
          const controls = Array.from(
            event.currentTarget.querySelectorAll<HTMLElement>(
              "button:not(:disabled), input:not(:disabled), a[href]",
            ),
          );
          const first = controls[0],
            last = controls[controls.length - 1];
          if (!first) {
            event.preventDefault();
            return;
          }
          if (
            event.shiftKey &&
            (document.activeElement === first ||
              document.activeElement === dialog.current)
          ) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }}
        onCancel={(event) => {
          event.preventDefault();
          if (!executing.current) finish(false);
        }}
      >
        {options && (
          <>
            <h2 id={title}>{options.title}</h2>
            <p id={description}>{options.description}</p>
            {options.confirmText && (
              <label className="field">
                <span>Type {options.confirmText} to confirm</span>
                <input
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  disabled={busy}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
            )}
            {error && (
              <p className="banner error" role="alert">
                {error}
              </p>
            )}
            <div className="confirmation-actions">
              <button
                type="button"
                className="btn quiet"
                ref={cancel}
                disabled={busy}
                onClick={() => finish(false)}
              >
                {options.cancelLabel ?? "Cancel"}
              </button>
              <button
                type="button"
                className={`btn ${options.intent === "warning" ? "confirmation-warning" : "danger"}`}
                aria-label={options.actionLabel}
                aria-busy={busy}
                disabled={
                  busy ||
                  Boolean(
                    options.confirmText && text.trim() !== options.confirmText,
                  )
                }
                onClick={() => void execute()}
              >
                <span className={busy ? "confirmation-label-busy" : undefined}>
                  {options.actionLabel}
                </span>
                {busy && <span className="spinner" aria-hidden="true" />}
              </button>
            </div>
          </>
        )}
      </dialog>
    </Context.Provider>
  );
}
