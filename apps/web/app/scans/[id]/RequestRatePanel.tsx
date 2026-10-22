"use client";

import { memo, useState } from "react";

const RATES = [1, 2, 5, 10, 20, 50, 100];

function RequestRatePanelImpl({
  value,
  running,
  onSave,
  managed = false,
}: {
  value: number;
  running: boolean;
  onSave: (requestsPerSecond: number) => Promise<void>;
  /** The project file sets the rate, so the buttons only show what it chose. */
  managed?: boolean;
}) {
  const [busy, setBusy] = useState(false);

  async function choose(rate: number) {
    if (rate === value) return;
    setBusy(true);
    try {
      await onSave(rate);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="sched">
      <span className="muted-sm">Maximum traffic from this scan:</span>
      {RATES.map((rate) => (
        <button
          key={rate}
          type="button"
          className={`btn sm${rate === value ? "" : " quiet"}`}
          aria-pressed={rate === value}
          disabled={busy || running || managed}
          onClick={() => choose(rate)}
          title={managed ? "Set by runpentests.yml" : undefined}
        >
          {rate} req/s
        </button>
      ))}
      {managed && (
        <span className="muted-sm" title="The request rate comes from the project file">
          set by runpentests.yml
        </span>
      )}
      <span className="grow" />
      <span className="muted-sm">
        Saved for manual and scheduled runs. Above 10 req/s, only against targets
        you know can take it; the server may enforce a lower ceiling.
      </span>
    </div>
  );
}

export const RequestRatePanel = memo(RequestRatePanelImpl);
