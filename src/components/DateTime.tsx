'use client';
import { useEffect, useState } from 'react';

/** Renders a timestamp in the viewer's locale after hydration (the server renders the UTC date). */
export function DateTime({ value, dateOnly = false }: { value: string | null | undefined; dateOnly?: boolean }) {
  const [text, setText] = useState(value ? value.slice(0, 10) : '—');
  useEffect(() => {
    if (!value) return;
    const d = new Date(value);
    setText(dateOnly ? d.toLocaleDateString() : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
  }, [value, dateOnly]);
  return (
    <time dateTime={value ?? undefined} title={value ?? undefined}>
      {text}
    </time>
  );
}
