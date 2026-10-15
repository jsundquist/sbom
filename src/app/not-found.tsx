import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';

export default function NotFound() {
  return (
    <Paper sx={{ p: 4, textAlign: 'center' }}>
      <Typography variant="h5" component="h1" gutterBottom>
        Not found
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 2 }}>
        That application, package or vulnerability isn&apos;t in any stored SBOM.
      </Typography>
      <Button href="/" variant="contained">
        Back to overview
      </Button>
    </Paper>
  );
}
