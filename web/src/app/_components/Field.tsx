"use client";

/**
 * Labelled text input.
 *
 * The `id` prop feeds both `<label htmlFor>` and `<input id>`, so the pairing
 * cannot drift apart the way hand-written pairs can. Every input on this
 * dashboard is reachable by its label — keep it that way.
 */
interface FieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  /**
   * `password` masks operator-typed credential material (the FIEL phrase, a
   * registered secret value). Masking is display-only — the caller is still
   * responsible for never logging or persisting the value.
   */
  type?: "text" | "password" | "number";
  placeholder?: string;
  helper?: string;
  min?: number;
  max?: number;
  disabled?: boolean;
}

export function Field({
  id,
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  helper,
  min,
  max,
  disabled,
}: FieldProps) {
  return (
    <div>
      <label
        htmlFor={id}
        className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
      >
        {label}
      </label>
      <input
        id={id}
        type={type}
        // `autoComplete="off"` is the deliberate choice for every field here,
        // including the masked ones. It is the correct signal to send: do not
        // autofill, do not offer to remember. It is best-effort — some browsers
        // ignore `off` on password inputs — but `new-password` would be worse,
        // because that actively invites the browser's own password manager to
        // save a FIEL phrase, which is exactly what ADR 0004 rules out.
        autoComplete="off"
        className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
        placeholder={placeholder}
        value={value}
        min={min}
        max={max}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      />
      {helper && (
        <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">{helper}</p>
      )}
    </div>
  );
}
