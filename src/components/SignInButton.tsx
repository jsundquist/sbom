'use client';
import Button from '@mui/material/Button';
import GitHubIcon from '@mui/icons-material/GitHub';
import { signIn } from 'next-auth/react';

export function SignInButton() {
  return (
    <Button variant="contained" size="large" startIcon={<GitHubIcon />} onClick={() => void signIn('github')}>
      Sign in with GitHub
    </Button>
  );
}
