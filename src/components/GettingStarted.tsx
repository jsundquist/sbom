import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';

const Code = ({ children }: { children: string }) => (
  <Box
    component="pre"
    sx={{ p: 2, bgcolor: 'background.default', border: 1, borderColor: 'divider', borderRadius: 1, overflowX: 'auto', fontSize: 13, m: 0 }}
  >
    {children}
  </Box>
);

export function GettingStarted({ origin }: { origin: string }) {
  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        No SBOMs uploaded yet
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 2 }}>
        Add the upload action to a repository&apos;s workflow. It generates a CycloneDX SBOM with Syft (or uses GitHub&apos;s dependency
        graph) and sends it here.
      </Typography>
      <Code>{`# .github/workflows/sbom.yml
on:
  push:
    branches: [main]
jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: jsundquist/sbom@main
        with:
          dashboard-url: ${origin}
          api-token: \${{ secrets.SBOM_DASHBOARD_TOKEN }}  # only if UPLOAD_TOKENS is set`}</Code>
      <Typography color="text.secondary" sx={{ my: 2 }}>
        Or upload any CycloneDX / SPDX JSON file directly:
      </Typography>
      <Code>{`curl -X POST "${origin}/api/v1/sboms?project=my-app&version=1.0.0" \\
  -H "Content-Type: application/json" \\
  --data-binary @sbom.cdx.json`}</Code>
    </Paper>
  );
}
