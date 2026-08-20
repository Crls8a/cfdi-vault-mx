"use client";

/**
 * Labelled `<select>`, the dropdown counterpart to `Field`.
 *
 * Same contract as `Field`: the `id` prop feeds both `<label htmlFor>` and
 * `<select id>`, so the pairing cannot drift apart and every control on this
 * dashboard stays reachable by its label.
 */
interface SelectFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: readonly string[];
}

export function SelectField({
  id,
  label,
  value,
  onChange,
  options,
}: SelectFieldProps) {
  return (
    <div>
      <label
        htmlFor={id}
        className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
      >
        {label}
      </label>
      <select
        id={id}
        className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </div>
  );
}
