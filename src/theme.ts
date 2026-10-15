'use client';
import { createTheme } from '@mui/material/styles';

declare module '@mui/material/styles' {
  interface Palette {
    severity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN', string>;
  }
  interface PaletteOptions {
    severity?: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN', string>;
  }
}

// Severity colors are status colors: always paired with an icon and a text label.
const severity = { CRITICAL: '#d03b3b', HIGH: '#ec835a', MEDIUM: '#fab219', LOW: '#6b8fd6', UNKNOWN: '#a3a29c' };

export const theme = createTheme({
  cssVariables: { colorSchemeSelector: 'class' },
  colorSchemes: {
    light: { palette: { primary: { main: '#2a5bd7' }, background: { default: '#f7f7f5', paper: '#ffffff' }, severity } },
    dark: { palette: { primary: { main: '#7ea2f5' }, background: { default: '#0d0d0d', paper: '#1a1a19' }, severity } },
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    h4: { fontWeight: 700, fontSize: '1.6rem' },
    h6: { fontWeight: 600, fontSize: '1.05rem' },
  },
  components: {
    MuiPaper: { defaultProps: { variant: 'outlined' } },
    MuiChip: { styleOverrides: { root: { fontWeight: 600 } } },
  },
});
