import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';

export function StatTile({ label, value, hint, children }: { label: string; value: React.ReactNode; hint?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <Paper sx={{ p: 2, height: '100%' }}>
      <Typography variant="overline" color="text.secondary" sx={{ lineHeight: 1.5 }}>
        {label}
      </Typography>
      <Typography variant="h4" component="p">
        {value}
      </Typography>
      {hint && (
        <Typography variant="body2" color="text.secondary">
          {hint}
        </Typography>
      )}
      {children}
    </Paper>
  );
}
