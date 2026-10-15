import type { Metadata } from 'next';
import { AppRouterCacheProvider } from '@mui/material-nextjs/v16-appRouter';
import InitColorSchemeScript from '@mui/material/InitColorSchemeScript';
import Container from '@mui/material/Container';
import { NavBar } from '@/components/NavBar';
import { Providers } from '@/components/Providers';

export const metadata: Metadata = {
  title: 'SBOM Dashboard',
  description: 'Software bills of materials, vulnerable packages and outdated dependencies across applications.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <InitColorSchemeScript attribute="class" />
        <AppRouterCacheProvider>
          <Providers>
            <NavBar />
            <Container maxWidth="xl" component="main" sx={{ py: 3 }}>
              {children}
            </Container>
          </Providers>
        </AppRouterCacheProvider>
      </body>
    </html>
  );
}
