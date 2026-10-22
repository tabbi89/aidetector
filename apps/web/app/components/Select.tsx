"use client";

import { useId } from "react";
import * as Primitive from "@radix-ui/react-select";
import styles from "./Select.module.css";

type Option = {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
};
const ALL = "__all__";

/** Authored catalogue filters; Radix owns focus, keyboard, typeahead and placement. */
export function Select({
  label,
  value,
  onChange,
  options,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Option[];
  disabled?: boolean;
}) {
  const id = useId();
  const selected =
    options.find((option) => option.value === value) ?? options[0];
  return (
    <div className={styles.field}>
      <label id={`${id}-label`} htmlFor={id}>
        {label}
      </label>
      <Primitive.Root
        value={value || ALL}
        onValueChange={(next) => onChange(next === ALL ? "" : next)}
        disabled={disabled}
      >
        <Primitive.Trigger
          id={id}
          aria-labelledby={`${id}-label`}
          className={styles.trigger}
          data-value={value}
        >
          <Primitive.Value>{selected?.label}</Primitive.Value>
          <Primitive.Icon className={styles.chevron}>
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="m4 6 4 4 4-4"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </Primitive.Icon>
        </Primitive.Trigger>
        <Primitive.Portal>
          <Primitive.Content
            className={styles.menu}
            position="popper"
            align="start"
            sideOffset={6}
            collisionPadding={12}
            aria-label={label}
          >
            <Primitive.ScrollUpButton
              className={styles.scroll}
              aria-label="Scroll options up"
            >
              ⌃
            </Primitive.ScrollUpButton>
            <Primitive.Viewport className={styles.viewport}>
              {options.map((option) => (
                <Primitive.Item
                  key={option.value}
                  value={option.value || ALL}
                  textValue={option.label}
                  disabled={option.disabled}
                  className={styles.option}
                >
                  <div className={styles.copy}>
                    <Primitive.ItemText>{option.label}</Primitive.ItemText>
                    {option.description && (
                      <span className={styles.description}>
                        {option.description}
                      </span>
                    )}
                  </div>
                  <Primitive.ItemIndicator
                    className={styles.check}
                    aria-hidden="true"
                  >
                    ✓
                  </Primitive.ItemIndicator>
                </Primitive.Item>
              ))}
            </Primitive.Viewport>
            <Primitive.ScrollDownButton
              className={styles.scroll}
              aria-label="Scroll options down"
            >
              ⌄
            </Primitive.ScrollDownButton>
          </Primitive.Content>
        </Primitive.Portal>
      </Primitive.Root>
    </div>
  );
}
