import Box from '@mui/material/Box';
import Link from '@mui/material/Link';
import Typography from '@mui/material/Typography';
import type { PageGate } from '@/server/auth';
import { SignInButton } from '@/components/SignInButton';

/** Rendered in place of a page's content when the viewer is not the owner. Deliberately names nothing about the app. */
export function AccessGate({ gate }: { gate: PageGate }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, py: 10, textAlign: 'center' }}>
      {gate.kind === 'sign-in' && <SignInButton />}
      {gate.kind === 'denied' && (
        <>
          <Typography variant="h5" component="h1">
            Access denied
          </Typography>
          <Typography color="text.secondary">
            {gate.login ? (
              <>
                Signed in as <strong>{gate.login}</strong>, which is not permitted here.
              </>
            ) : (
              'This account is not permitted here.'
            )}
          </Typography>
          <Link href="/api/auth/signout">Sign out</Link>
        </>
      )}
      {gate.kind === 'unavailable' && <Typography color="text.secondary">Reads are disabled: owner sign-in is not configured.</Typography>}
    </Box>
  );
}
