'use client';
import NextLink from 'next/link';
import { usePathname } from 'next/navigation';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { useColorScheme } from '@mui/material/styles';
import DarkModeIcon from '@mui/icons-material/DarkModeOutlined';
import LightModeIcon from '@mui/icons-material/LightModeOutlined';
import Inventory2Icon from '@mui/icons-material/Inventory2Outlined';

const LINKS = [
  { href: '/', label: 'Overview' },
  { href: '/projects', label: 'Applications' },
  { href: '/packages', label: 'Packages' },
  { href: '/vulnerabilities', label: 'Vulnerabilities' },
];

export function NavBar() {
  const pathname = usePathname();
  const { mode, systemMode, setMode } = useColorScheme();
  const resolved = mode === 'system' ? systemMode : mode;
  const isActive = (href: string) => (href === '/' ? pathname === '/' : pathname.startsWith(href));

  return (
    <AppBar position="sticky" color="inherit" elevation={0} sx={{ borderBottom: 1, borderColor: 'divider' }}>
      <Toolbar sx={{ columnGap: 2, flexWrap: 'wrap' }}>
        <Box component={NextLink} href="/" sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.primary', textDecoration: 'none' }}>
          <Inventory2Icon color="primary" />
          <Typography variant="h6" component="span">
            SBOM Dashboard
          </Typography>
        </Box>
        <Box component="nav" sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', flexGrow: 1, order: { xs: 3, md: 0 }, flexBasis: { xs: '100%', md: 'auto' }, pb: { xs: 1, md: 0 } }}>
          {LINKS.map((l) => (
            <Button
              key={l.href}
              component={NextLink}
              href={l.href}
              color={isActive(l.href) ? 'primary' : 'inherit'}
              variant={isActive(l.href) ? 'contained' : 'text'}
              disableElevation
              size="small"
              aria-current={isActive(l.href) ? 'page' : undefined}
            >
              {l.label}
            </Button>
          ))}
        </Box>
        {resolved && (
          <Tooltip title={resolved === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            <IconButton sx={{ ml: 'auto' }} onClick={() => setMode(resolved === 'dark' ? 'light' : 'dark')} aria-label="Toggle color mode">
              {resolved === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
        )}
      </Toolbar>
    </AppBar>
  );
}
