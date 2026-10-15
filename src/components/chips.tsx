'use client';
import Chip, { type ChipProps } from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Tooltip from '@mui/material/Tooltip';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import ReportIcon from '@mui/icons-material/Report';
import InfoIcon from '@mui/icons-material/Info';
import HelpIcon from '@mui/icons-material/Help';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import UpgradeIcon from '@mui/icons-material/Upgrade';
import HourglassIcon from '@mui/icons-material/HourglassEmpty';
import LocalFireDepartmentIcon from '@mui/icons-material/LocalFireDepartment';
import type { Severity } from '@/lib/severity';
import type { UpdateType } from '@/lib/version';
import type { KevInfo } from '@/server/inventory';

const SEVERITY_ICON: Record<Severity, React.ReactElement> = {
  CRITICAL: <ReportIcon />,
  HIGH: <ErrorIcon />,
  MEDIUM: <WarningIcon />,
  LOW: <InfoIcon />,
  UNKNOWN: <HelpIcon />,
};

const LABEL: Record<Severity, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Unknown' };
export const severityLabel = (s: Severity) => LABEL[s];

/** Severity shown as icon + label; color is never the only signal. */
export function SeverityChip({
  severity,
  count,
  score,
  size = 'small',
}: {
  severity: Severity;
  count?: number;
  score?: number | null;
  size?: ChipProps['size'];
}) {
  const label = `${LABEL[severity]}${count !== undefined ? ` ${count}` : ''}${score ? ` ${score.toFixed(1)}` : ''}`;
  return (
    <Chip
      size={size}
      variant="outlined"
      icon={SEVERITY_ICON[severity]}
      label={label}
      sx={{ '& .MuiChip-icon': { color: `severity.${severity}` }, borderColor: `severity.${severity}` }}
    />
  );
}

export function SeverityCounts({ counts, emptyLabel = 'No known CVEs' }: { counts: Record<Severity, number>; emptyLabel?: string }) {
  const entries = (Object.entries(counts) as [Severity, number][]).filter(([, n]) => n > 0);
  if (!entries.length) {
    return <OkChip label={emptyLabel} />;
  }
  return (
    <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
      {entries.map(([s, n]) => (
        <SeverityChip key={s} severity={s} count={n} />
      ))}
    </Stack>
  );
}

export function OkChip({ label }: { label: string }) {
  return <Chip size="small" variant="outlined" color="success" icon={<CheckCircleIcon />} label={label} />;
}

const UPDATE_COLOR: Record<UpdateType, ChipProps['color']> = { major: 'error', minor: 'warning', patch: 'info' };

export function OutdatedChip({ outdated, latest }: { outdated: UpdateType | null; latest?: string | null }) {
  if (!outdated) {
    return latest ? <OkChip label="Up to date" /> : null;
  }
  const chip = <Chip size="small" variant="outlined" color={UPDATE_COLOR[outdated]} icon={<UpgradeIcon />} label={`${outdated} update`} />;
  return latest ? <Tooltip title={`Latest: ${latest}`}>{chip}</Tooltip> : chip;
}

export function PendingChip({ label = 'Scanning…' }: { label?: string }) {
  return <Chip size="small" variant="outlined" icon={<HourglassIcon />} label={label} />;
}

/** Known to be exploited in the wild (CISA KEV). Details are in the tooltip. */
export function KevChip({ kev, count, size = 'small' }: { kev?: KevInfo | null; count?: number; size?: ChipProps['size'] }) {
  const label = count !== undefined ? `${count} known exploited` : 'Exploited';
  const chip = <Chip size={size} color="error" icon={<LocalFireDepartmentIcon />} label={label} />;
  if (!kev) {
    return chip;
  }
  const parts = [
    'Known exploited (CISA KEV)',
    `Added ${kev.dateAdded}`,
    kev.dueDate ? `Remediation due ${kev.dueDate}` : null,
    kev.ransomware ? 'Used in ransomware campaigns' : null,
  ].filter(Boolean);
  return <Tooltip title={parts.join(' · ')}>{chip}</Tooltip>;
}
