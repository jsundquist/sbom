'use client';
import NextLink from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';

export type ProjectTab = 'packages' | 'dependencies';

/** Switches the application page between its package list and dependency tree, keeping the selected SBOM upload. */
export function ProjectTabs({ value }: { value: ProjectTab }) {
  const pathname = usePathname();
  const params = useSearchParams();
  const href = (tab: ProjectTab) => {
    const next = new URLSearchParams(params);
    if (tab === 'packages') {
      next.delete('tab');
    } else {
      next.set('tab', tab);
    }
    const query = next.toString();
    return query ? `${pathname}?${query}` : pathname;
  };
  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
      <Tabs value={value} aria-label="Application views">
        <Tab component={NextLink} href={href('packages')} value="packages" label="Packages" />
        <Tab component={NextLink} href={href('dependencies')} value="dependencies" label="Dependencies" />
      </Tabs>
    </Box>
  );
}
