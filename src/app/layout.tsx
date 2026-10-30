import type { Metadata } from 'next';
import { AppRouterCacheProvider } from '@mui/material-nextjs/v16-appRouter';
import InitColorSchemeScript from '@mui/material/InitColorSchemeScript';
import Container from '@mui/material/Container';
import { NavBar } from '@/components/NavBar';
import { Providers } from '@/components/Providers';
import { requireOwnerPage } from '@/server/auth';

// A gated viewer learns nothing about what the app holds: the neutral text names neither SBOMs nor vulnerabilities.
export async function generateMetadata(): Promise<Metadata> {
  if ((await requireOwnerPage()) !== null) {
    return { title: 'Dashboard', description: 'Sign in required.' };
  }
  return {
    title: 'SBOM Dashboard',
    description: 'Software bills of materials, vulnerable packages and outdated dependencies across applications.',
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // No nav for a gated viewer: it would list what the app contains.
  const gated = (await requireOwnerPage()) !== null;
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <InitColorSchemeScript attribute="class" />
        <AppRouterCacheProvider>
          <Providers>
            {!gated && <NavBar />}
            <Container maxWidth="xl" component="main" sx={{ py: 3 }}>
              {children}
            </Container>
          </Providers>
        </AppRouterCacheProvider>
      </body>
    </html>
  );
}
