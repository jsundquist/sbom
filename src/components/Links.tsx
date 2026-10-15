'use client';
import NextLink from 'next/link';
import Link from '@mui/material/Link';

export function AppLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link component={NextLink} href={href} underline="hover">
      {children}
    </Link>
  );
}
