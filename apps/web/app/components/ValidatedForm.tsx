"use client";

import {
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ComponentProps,
} from "react";

type Field = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
type FieldError = { field: Field; message: string };

function errorsIn(form: HTMLFormElement): FieldError[] {
  return Array.from(form.elements).flatMap((element) => {
    if (
      !(
        element instanceof HTMLInputElement ||
        element instanceof HTMLSelectElement ||
        element instanceof HTMLTextAreaElement
      ) ||
      !element.willValidate
    )
      return [];
    const validity = element.validity;
    if (validity.valid) return [];
    const label =
      element.getAttribute("aria-label") ||
      Array.from(element.labels?.[0]?.childNodes ?? [])
        .filter(
          (node) =>
            node.nodeType === Node.TEXT_NODE ||
            (node instanceof HTMLElement && node.tagName === "SPAN"),
        )
        .map((node) => node.textContent)
        .join(" ")
        .trim() ||
      "This field";
    const hint = validity.valueMissing
      ? "Enter a value."
      : validity.typeMismatch
        ? element instanceof HTMLInputElement && element.type === "email"
          ? "Enter a valid email address."
          : "Enter a complete URL, including https://."
        : validity.tooShort
          ? `Use at least ${(element as HTMLInputElement).minLength} characters.`
          : validity.tooLong
            ? `Use no more than ${(element as HTMLInputElement).maxLength} characters.`
            : validity.rangeUnderflow ||
                validity.rangeOverflow ||
                validity.stepMismatch ||
                validity.badInput
              ? "Enter a number within the allowed range."
              : "Check the required format.";
    return [{ field: element, message: `${label}: ${hint}` }];
  });
}

/** Own constraint feedback while keeping native field semantics and metadata. */
export function ValidatedForm({
  children,
  onSubmit,
  onInput,
  ...props
}: ComponentProps<"form">) {
  const ref = useRef<HTMLFormElement>(null);
  const attempted = useRef(false);
  const composing = useRef(false);
  const [errors, setErrors] = useState<FieldError[]>([]);
  const id = useId();

  useLayoutEffect(() => {
    const previous = errors.map(({ field }, index) => {
      const invalid = field.getAttribute("aria-invalid");
      const describedBy = field.getAttribute("aria-describedby");
      field.setAttribute("aria-invalid", "true");
      field.setAttribute(
        "aria-describedby",
        [describedBy, `${id}-${index}`].filter(Boolean).join(" "),
      );
      return { field, invalid, describedBy };
    });
    return () =>
      previous.forEach(({ field, invalid, describedBy }) => {
        if (invalid === null) field.removeAttribute("aria-invalid");
        else field.setAttribute("aria-invalid", invalid);
        if (describedBy === null) field.removeAttribute("aria-describedby");
        else field.setAttribute("aria-describedby", describedBy);
      });
  }, [errors, id]);

  return (
    <form
      {...props}
      ref={ref}
      noValidate
      onCompositionStart={() => {
        composing.current = true;
      }}
      onCompositionEnd={() => {
        composing.current = false;
      }}
      onInput={(event) => {
        onInput?.(event);
        if (attempted.current && ref.current) setErrors(errorsIn(ref.current));
      }}
      onSubmit={(event) => {
        event.preventDefault();
        if (composing.current) return;
        attempted.current = true;
        const next = errorsIn(event.currentTarget);
        setErrors(next);
        if (next.length) {
          next[0].field.focus();
          return;
        }
        onSubmit?.(event);
      }}
    >
      {errors.length > 0 && (
        <div className="form-validation" role="alert">
          <strong>Check the highlighted fields.</strong>
          <ul>
            {errors.map(({ field, message }, index) => (
              <li key={index} id={`${id}-${index}`}>
                <button type="button" onClick={() => field.focus()}>
                  {message}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {children}
    </form>
  );
}
