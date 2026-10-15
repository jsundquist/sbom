'use client';
import { useSyncExternalStore } from 'react';

const subscribe = () => () => {};

/** Renders a timestamp in the viewer's locale after hydration (the server renders the UTC date). */
export function DateTime({ value, dateOnly = false }: { value: string | null | undefined; dateOnly?: boolean }) {
  const text = useSyncExternalStore(
    subscribe,
    () => {
      if (!value) return '—';
      const d = new Date(value);
      return dateOnly ? d.toLocaleDateString() : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    },
    () => (value ? value.slice(0, 10) : '—'),
  );
  return (
    <time dateTime={value ?? undefined} title={value ?? undefined}>
      {text}
    </time>
  );
}
