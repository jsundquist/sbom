'use client';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { type Palette, useColorScheme, useTheme } from '@mui/material/styles';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { ProjectSummary, SeverityCounts } from '@/server/inventory';
import { SEVERITIES, type Severity } from '@/lib/severity';
import { severityLabel } from './chips';

// SVG attributes can't use CSS variables, so resolve concrete colors for the active color scheme.
function useChartColors() {
  const theme = useTheme();
  const { mode, systemMode } = useColorScheme();
  const scheme = (mode === 'system' ? systemMode : mode) ?? 'light';
  const schemes = (theme as unknown as { colorSchemes?: Record<string, { palette: Palette }> }).colorSchemes;
  const palette = schemes?.[scheme]?.palette ?? theme.palette;
  return {
    severity: palette.severity,
    axis: palette.text.secondary,
    grid: palette.divider,
    surface: palette.background.paper,
    text: palette.text.primary,
  };
}

const tooltipStyle = (c: ReturnType<typeof useChartColors>) => ({
  contentStyle: { background: c.surface, border: `1px solid ${c.grid}`, borderRadius: 8, color: c.text },
  itemStyle: { color: c.text },
  cursor: { fill: c.grid, opacity: 0.4 },
});

/** Count of distinct vulnerabilities per severity. */
export function SeverityBarChart({ counts }: { counts: SeverityCounts }) {
  const c = useChartColors();
  const data = SEVERITIES.map((s) => ({ severity: severityLabel(s), key: s, count: counts[s] }));
  return (
    <Box sx={{ height: 220 }} role="img" aria-label={`Vulnerabilities by severity: ${data.map((d) => `${d.severity} ${d.count}`).join(', ')}`}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 16, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke={c.grid} />
          <XAxis dataKey="severity" tick={{ fill: c.axis, fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis allowDecimals={false} tick={{ fill: c.axis, fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip {...tooltipStyle(c)} formatter={(v) => [v, 'Vulnerabilities']} />
          <Bar
            dataKey="count"
            radius={[4, 4, 0, 0]}
            maxBarSize={48}
            label={{ position: 'top', fill: c.text, fontSize: 12 }}
            shape={(props: { x?: number; y?: number; width?: number; height?: number; payload?: { key: Severity } }) => (
              <path
                d={roundedTop(props.x ?? 0, props.y ?? 0, props.width ?? 0, props.height ?? 0)}
                fill={c.severity[props.payload?.key ?? 'UNKNOWN']}
              />
            )}
          />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

function roundedTop(x: number, y: number, w: number, h: number, r = 4) {
  if (h <= 0) {return '';}
  const rr = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

/** Stacked horizontal bars: vulnerabilities per application, split by severity. */
export function ProjectRiskChart({ projects, limit = 8 }: { projects: ProjectSummary[]; limit?: number }) {
  const c = useChartColors();
  const data = projects
    .filter((p) => p.stats.vulnerabilities > 0)
    .sort((a, b) => b.stats.vulnerabilities - a.stats.vulnerabilities)
    .slice(0, limit)
    .map((p) => ({ name: p.name, ...p.stats.severity }));
  if (!data.length) {
    return (
      <Typography color="text.secondary" sx={{ py: 4, textAlign: 'center' }}>
        No vulnerable applications.
      </Typography>
    );
  }
  const present = SEVERITIES.filter((s) => data.some((d) => d[s] > 0));
  return (
    <Box sx={{ height: 60 + data.length * 36 }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }} barCategoryGap={8}>
          <CartesianGrid horizontal={false} stroke={c.grid} />
          <XAxis type="number" allowDecimals={false} tick={{ fill: c.axis, fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="name" width={130} tick={{ fill: c.text, fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip {...tooltipStyle(c)} />
          <Legend wrapperStyle={{ fontSize: 12 }} iconType="square" formatter={(value) => <span style={{ color: c.axis }}>{value}</span>} />
          {present.map((s) => (
            <Bar key={s} dataKey={s} name={severityLabel(s)} stackId="sev" fill={c.severity[s]} stroke={c.surface} strokeWidth={2} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}
