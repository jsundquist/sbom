import { z } from 'zod';

/** Where an uploaded SBOM says it was built for or deployed to, for example `staging` (ticket G-006). Stored per SBOM, never shown. */
export const MAX_ENVIRONMENT_LENGTH = 40;

export const environmentField = z
  .string()
  .trim()
  .toLowerCase()
  .max(MAX_ENVIRONMENT_LENGTH, { error: `environment must be at most ${MAX_ENVIRONMENT_LENGTH} characters` })
  .regex(/^[a-z0-9_-]*$/, { error: 'environment may only use a-z, 0-9, underscore and hyphen' })
  .optional()
  .transform((v) => v || undefined);
