import { notFound } from 'next/navigation';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Link from '@mui/material/Link';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { getDb } from '@/db';
import { getVulnerability } from '@/server/inventory';
import { KevChip, SeverityChip } from '@/components/chips';
import { DateTime } from '@/components/DateTime';
import { AppLink } from '@/components/Links';
import { packageHref, projectHref } from '@/lib/routes';
import { PageHeader } from '@/components/PageHeader';
import { formatEpss } from '@/lib/epss';

export const dynamic = 'force-dynamic';

export default async function VulnerabilityPage({ params }: { params: Promise<{ id: string }> }) {
  const vuln = await getVulnerability(getDb(), decodeURIComponent((await params).id));
  if (!vuln) {
    notFound();
  }

  return (
    <>
      <PageHeader
        title={vuln.cve ?? vuln.id}
        crumbs={[{ href: '/vulnerabilities', label: 'Vulnerabilities' }]}
        subtitle={vuln.summary}
        actions={
          <Stack direction="row" spacing={1}>
            {vuln.kev && <KevChip kev={vuln.kev} size="medium" />}
            <SeverityChip severity={vuln.severity} score={vuln.score} size="medium" />
          </Stack>
        }
      />
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 8 }}>
          <Paper sx={{ p: 2, mb: 2 }}>
            <Typography variant="h6" component="h2" gutterBottom>
              Affected packages
            </Typography>
            <List dense disablePadding>
              {vuln.affected.map((a) => (
                <ListItem key={`${a.packageKey}@${a.version}`} disableGutters>
                  <ListItemText
                    primary={
                      <>
                        <AppLink href={packageHref(a.packageKey)}>{a.name}</AppLink> {a.version}
                      </>
                    }
                    secondary={
                      a.fixVersion
                        ? `Upgrade to ${a.fixVersion} or later`
                        : a.fixedVersions.length
                          ? `Fixed in ${a.fixedVersions.join(', ')}`
                          : 'No fixed version published'
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
          {vuln.details && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" component="h2" gutterBottom>
                Details
              </Typography>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', color: 'text.secondary', maxHeight: 480, overflow: 'auto' }}>
                {vuln.details}
              </Typography>
            </Paper>
          )}
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <Paper sx={{ p: 2, mb: 2 }}>
            <Typography variant="h6" component="h2" gutterBottom>
              Applications
            </Typography>
            <Stack spacing={0.5}>
              {vuln.projects.length ? (
                vuln.projects.map((p) => (
                  <AppLink key={p.id} href={projectHref(p.id)}>
                    {p.name}
                  </AppLink>
                ))
              ) : (
                <Typography color="text.secondary">Not used by any application&apos;s latest SBOM.</Typography>
              )}
            </Stack>
          </Paper>
          <Paper sx={{ p: 2 }}>
            <Box component="dl" sx={{ m: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '4px 16px', fontSize: 14 }}>
              <Box component="dt" sx={{ color: 'text.secondary' }}>
                ID
              </Box>
              <Box component="dd" sx={{ m: 0 }}>
                {vuln.id}
              </Box>
              {vuln.aliases.length > 0 && (
                <>
                  <Box component="dt" sx={{ color: 'text.secondary' }}>
                    Aliases
                  </Box>
                  <Box component="dd" sx={{ m: 0 }}>
                    {vuln.aliases.join(', ')}
                  </Box>
                </>
              )}
              {vuln.vector && (
                <>
                  <Box component="dt" sx={{ color: 'text.secondary' }}>
                    Vector
                  </Box>
                  <Box component="dd" sx={{ m: 0, wordBreak: 'break-all', fontFamily: 'monospace', fontSize: 12 }}>
                    {vuln.vector}
                  </Box>
                </>
              )}
              {vuln.kev && (
                <>
                  <Box component="dt" sx={{ color: 'text.secondary' }}>
                    Exploited
                  </Box>
                  <Box component="dd" sx={{ m: 0 }}>
                    CISA KEV, added {vuln.kev.dateAdded}
                    {vuln.kev.dueDate ? `, remediation due ${vuln.kev.dueDate}` : ''}
                    {vuln.kev.ransomware ? ', used in ransomware campaigns' : ''}
                  </Box>
                </>
              )}
              {vuln.epss && (
                <>
                  <Box component="dt" sx={{ color: 'text.secondary' }}>
                    EPSS
                  </Box>
                  <Box component="dd" sx={{ m: 0 }}>
                    {formatEpss(vuln.epss.score)} chance of exploitation in the next 30 days (higher than{' '}
                    {Math.round(vuln.epss.percentile * 100)}% of scored CVEs)
                  </Box>
                </>
              )}
              <Box component="dt" sx={{ color: 'text.secondary' }}>
                Published
              </Box>
              <Box component="dd" sx={{ m: 0 }}>
                <DateTime value={vuln.published} dateOnly />
              </Box>
              <Box component="dt" sx={{ color: 'text.secondary' }}>
                Modified
              </Box>
              <Box component="dd" sx={{ m: 0 }}>
                <DateTime value={vuln.modified} dateOnly />
              </Box>
            </Box>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>
              References
            </Typography>
            <Stack spacing={0.5} sx={{ mt: 0.5 }}>
              <Link
                href={`https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`}
                target="_blank"
                rel="noreferrer"
                underline="hover"
                sx={{ display: 'inline-flex', gap: 0.5, alignItems: 'center' }}
              >
                osv.dev <OpenInNewIcon sx={{ fontSize: 14 }} />
              </Link>
              {vuln.references.map((r) => (
                <Link
                  key={r.url}
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  underline="hover"
                  sx={{ wordBreak: 'break-all', fontSize: 13 }}
                >
                  {r.url}
                </Link>
              ))}
            </Stack>
          </Paper>
        </Grid>
      </Grid>
    </>
  );
}
