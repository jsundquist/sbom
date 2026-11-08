// OpenSSF Scorecard helpers shared by the worker (what to store) and server (how to report it).
import { isVersionCheckable } from './coverage';

export interface ScorecardCheck {
  name: string;
  score: number;
  reason?: string | null;
}

export type ScorecardStatus = 'checked' | 'pending' | 'unsupported';

/** The lowest scored checks. Scorecard reports -1 for a check it could not run, which says nothing about the repo. */
export function weakestChecks(checks: ScorecardCheck[], limit = 3): ScorecardCheck[] {
  return checks
    .filter((c) => c.score >= 0)
    .sort((a, b) => a.score - b.score)
    .slice(0, limit);
}

/** "unsupported" covers ecosystems deps.dev does not index and checked packages with no source repo or no scorecard. */
export function scorecardStatus(ecosystem: string | null, checkedAt: Date | null, score: number | null): ScorecardStatus {
  if (!isVersionCheckable(ecosystem)) {
    return 'unsupported';
  }
  if (!checkedAt) {
    return 'pending';
  }
  return score === null ? 'unsupported' : 'checked';
}
