import Box from '@mui/material/Box';
import Breadcrumbs from '@mui/material/Breadcrumbs';
import Typography from '@mui/material/Typography';
import { AppLink } from './Links';

export function PageHeader({
  title,
  subtitle,
  crumbs,
  actions,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  crumbs?: { href: string; label: string }[];
  actions?: React.ReactNode;
}) {
  return (
    <Box sx={{ mb: 3 }}>
      {crumbs && (
        <Breadcrumbs sx={{ mb: 1, fontSize: 14 }}>
          {crumbs.map((c) => (
            <AppLink key={c.href} href={c.href}>
              {c.label}
            </AppLink>
          ))}
        </Breadcrumbs>
      )}
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <Typography variant="h4" component="h1" sx={{ wordBreak: 'break-word' }}>
            {title}
          </Typography>
          {subtitle && (
            <Typography color="text.secondary" component="div" sx={{ mt: 0.5 }}>
              {subtitle}
            </Typography>
          )}
        </Box>
        {actions}
      </Box>
    </Box>
  );
}
