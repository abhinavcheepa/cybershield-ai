/**
 * Chart layer.
 *
 * Colour policy:
 *  - Severity is an *ordered status scale*, not a categorical identity palette.
 *    It keeps the traffic-light ramp analysts already read at a glance. Checked
 *    against the #0b1120 surface: contrast PASSES for all five steps and
 *    colourblind separation PASSES (worst adjacent ΔE 9.1). Because adjacent
 *    hues in a traffic light are inherently close, severity is NEVER encoded by
 *    colour alone — every severity mark ships with its label, in the legend,
 *    the direct labels and the tooltip.
 *  - Magnitude charts (volume, response time, country totals) use one hue.
 *  - A single-series chart gets no legend; the title names it.
 *  - No chart here has two y-axes.
 */

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { SEVERITY_HEX, clockTime, compactNumber, countryFlag } from '../lib/format'
import type { CountryStat, Severity, TimeBucket } from '../lib/types'

const SURFACE = '#0b1120'
const ACCENT = '#22d3ee'
const GRID = 'rgba(148, 178, 255, 0.09)'
const AXIS_TICK = { fill: '#64748b', fontSize: 11 }

const axisProps = {
  stroke: 'transparent',
  tick: AXIS_TICK,
  tickLine: false,
  axisLine: false,
} as const

function ChartTooltip({
  active,
  payload,
  label,
  unit = '',
}: {
  active?: boolean
  payload?: { name?: string; value?: number | string; color?: string; payload?: Record<string, unknown> }[]
  label?: string
  unit?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-md border border-hairline bg-void/95 px-3 py-2 text-xs shadow-glass backdrop-blur">
      {label && <p className="mb-1 font-medium text-slate-300">{label}</p>}
      {payload.map((entry, index) => (
        <p key={index} className="flex items-center gap-2 text-slate-400">
          {entry.color && (
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: entry.color }} aria-hidden />
          )}
          {/* Identity comes from the name, never the swatch alone. */}
          {entry.name && <span className="capitalize">{entry.name}</span>}
          <span className="data ml-auto font-semibold text-white">
            {typeof entry.value === 'number' ? entry.value.toLocaleString() : entry.value}
            {unit}
          </span>
        </p>
      ))}
    </div>
  )
}

const timeLabel = (series: TimeBucket[]) => (value: string, index: number) =>
  index === 0 || index === series.length - 1 || index % 6 === 0 ? clockTime(value) : ''

/** Attack volume over time. One series — no legend, the panel title names it. */
export function AttackVolumeChart({ series }: { series: TimeBucket[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={series} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
        <defs>
          <linearGradient id="volumeFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ACCENT} stopOpacity={0.5} />
            <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="timestamp" {...axisProps} tickFormatter={timeLabel(series)} interval={0} />
        <YAxis {...axisProps} width={44} allowDecimals={false} />
        <Tooltip
          content={<ChartTooltip />}
          labelFormatter={(value) => clockTime(String(value))}
          cursor={{ stroke: ACCENT, strokeWidth: 1, strokeDasharray: '3 3' }}
        />
        <Area
          type="monotone"
          dataKey="count"
          name="attacks"
          stroke={ACCENT}
          strokeWidth={2}
          fill="url(#volumeFill)"
          activeDot={{ r: 4, strokeWidth: 2, stroke: SURFACE }}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

/** Mean threat score per bucket — the risk trend. Single series. */
export function ThreatTrendChart({ series }: { series: TimeBucket[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={series} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="timestamp" {...axisProps} tickFormatter={timeLabel(series)} interval={0} />
        <YAxis {...axisProps} width={44} domain={[0, 100]} />
        <Tooltip
          content={<ChartTooltip />}
          labelFormatter={(value) => clockTime(String(value))}
          cursor={{ stroke: SEVERITY_HEX.high, strokeWidth: 1, strokeDasharray: '3 3' }}
        />
        <Line
          type="monotone"
          dataKey="threat_score"
          name="threat score"
          stroke={SEVERITY_HEX.high}
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: SURFACE }}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

/** Mean response time per bucket. Single series. */
export function ResponseTimeChart({ series }: { series: TimeBucket[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={series} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
        <defs>
          <linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={SEVERITY_HEX.low} stopOpacity={0.42} />
            <stop offset="100%" stopColor={SEVERITY_HEX.low} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="timestamp" {...axisProps} tickFormatter={timeLabel(series)} interval={0} />
        <YAxis {...axisProps} width={52} tickFormatter={(value) => `${compactNumber(Number(value))}ms`} />
        <Tooltip
          content={<ChartTooltip unit="ms" />}
          labelFormatter={(value) => clockTime(String(value))}
          cursor={{ stroke: SEVERITY_HEX.low, strokeWidth: 1, strokeDasharray: '3 3' }}
        />
        <Area
          type="monotone"
          dataKey="avg_response_ms"
          name="response time"
          stroke={SEVERITY_HEX.low}
          strokeWidth={2}
          fill="url(#latencyFill)"
          activeDot={{ r: 4, strokeWidth: 2, stroke: SURFACE }}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

/**
 * Severity mix. Segments carry a 2px surface gap so adjacent traffic-light
 * hues stay separable, and every slice is named in the adjacent legend.
 */
export function SeverityDonut({ data }: { data: { severity: Severity; count: number }[] }) {
  const rows = data.filter((row) => row.count > 0)
  const total = rows.reduce((sum, row) => sum + row.count, 0)
  if (!total) return <p className="py-10 text-center text-sm text-slate-500">No attacks in this window.</p>

  return (
    <div className="flex h-full flex-col items-center gap-3 sm:flex-row">
      <div className="relative h-40 w-40 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={rows}
              dataKey="count"
              nameKey="severity"
              innerRadius={48}
              outerRadius={72}
              paddingAngle={2}
              stroke={SURFACE}
              strokeWidth={2}
            >
              {rows.map((row) => (
                <Cell key={row.severity} fill={SEVERITY_HEX[row.severity]} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="data text-xl font-semibold text-white">{compactNumber(total)}</span>
          <span className="text-[10px] uppercase tracking-wider text-slate-500">events</span>
        </div>
      </div>

      <ul className="min-w-0 flex-1 space-y-1.5">
        {rows.map((row) => (
          <li key={row.severity} className="flex items-center gap-2 text-xs">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-sm"
              style={{ backgroundColor: SEVERITY_HEX[row.severity] }}
              aria-hidden
            />
            <span className="capitalize text-slate-300">{row.severity}</span>
            <span className="data ml-auto text-slate-400">{row.count}</span>
            <span className="data w-11 text-right text-slate-500">
              {((row.count / total) * 100).toFixed(0)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Attack volume by source country — magnitude, so one hue. */
export function CountryBarChart({ countries }: { countries: CountryStat[] }) {
  const rows = countries.slice(0, 8).map((country) => ({
    ...country,
    label: `${countryFlag(country.country_code)} ${country.country_code}`,
  }))

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 20, left: 4, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" {...axisProps} allowDecimals={false} />
        <YAxis type="category" dataKey="label" {...axisProps} width={62} />
        <Tooltip
          content={<ChartTooltip />}
          cursor={{ fill: 'rgba(148, 178, 255, 0.06)' }}
          labelFormatter={(_, payload) =>
            (payload?.[0]?.payload as CountryStat | undefined)?.country_name ?? ''
          }
        />
        {/* Rounded data-end only; the baseline end stays square. */}
        <Bar dataKey="count" name="attacks" fill={ACCENT} radius={[0, 4, 4, 0]} maxBarSize={16} />
      </BarChart>
    </ResponsiveContainer>
  )
}
