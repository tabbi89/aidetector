"use client";

import { useLayoutEffect, useRef, type ComponentProps } from "react";

/** Expands with content up to a readable editor height, then scrolls internally. */
export function ExpandingTextarea({
  value,
  onInput,
  style,
  className,
  ...props
}: ComponentProps<"textarea">) {
  const ref = useRef<HTMLTextAreaElement>(null);

  function resize() {
    const field = ref.current;
    if (!field || field.clientWidth === 0) return;
    field.style.height = "auto";
    const minimum = Number.parseFloat(getComputedStyle(field).minHeight) || 0;
    field.style.height = `${Math.max(minimum, Math.min(520, field.scrollHeight + field.offsetHeight - field.clientHeight))}px`;
  }

  useLayoutEffect(resize, [value]);
  useLayoutEffect(() => {
    const field = ref.current;
    if (!field) return;
    let width = 0;
    const observer = new ResizeObserver(([entry]) => {
      if (entry.contentRect.width !== width) {
        width = entry.contentRect.width;
        resize();
      }
    });
    observer.observe(field);
    return () => observer.disconnect();
  }, []);

  return (
    <textarea
      {...props}
      className={`resize-none ${className ?? ""}`}
      value={value}
      ref={ref}
      style={{ ...style, resize: "none" }}
      onInput={(event) => {
        resize();
        onInput?.(event);
      }}
    />
  );
}
