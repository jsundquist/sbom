/** EPSS score (probability of exploitation activity in the next 30 days, 0..1) as a percentage. */
export function formatEpss(score: number): string {
  if (score < 0.001) {
    return '<0.1%';
  }
  return `${(score * 100).toFixed(1).replace(/\.0$/, '')}%`;
}
