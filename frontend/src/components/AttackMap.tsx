// Leaflet's stylesheet belongs to this component, not to the global bundle:
// imported here it ships in the map's own chunk, so the ~15 KB only reaches
// browsers that actually open the map.
import 'leaflet/dist/leaflet.css'
import { useMemo } from 'react'
import { CircleMarker, MapContainer, Polyline, Popup, TileLayer, Tooltip } from 'react-leaflet'

import { SEVERITY_HEX, clockTime, countryFlag } from '../lib/format'
import type { AttackEvent, CountryStat } from '../lib/types'

type LatLng = [number, number]

/**
 * Quadratic bezier between two points, bowed away from the straight line.
 *
 * Leaflet only draws polylines, so a "great arc" is really a sampled curve.
 * The control point is offset perpendicular to the chord, scaled by distance,
 * which keeps short hops nearly flat and long ones satisfyingly curved.
 */
function arcPoints(from: LatLng, to: LatLng, segments = 48): LatLng[] {
  const [lat1, lon1] = from
  const [lat2, lon2] = to
  const midLat = (lat1 + lat2) / 2
  const midLon = (lon1 + lon2) / 2
  const dLat = lat2 - lat1
  const dLon = lon2 - lon1
  const distance = Math.hypot(dLat, dLon)
  const bow = Math.min(distance * 0.22, 26)

  // Perpendicular to the chord, normalised.
  const controlLat = midLat + (-dLon / (distance || 1)) * bow
  const controlLon = midLon + (dLat / (distance || 1)) * bow

  const points: LatLng[] = []
  for (let i = 0; i <= segments; i += 1) {
    const t = i / segments
    const inv = 1 - t
    points.push([
      inv * inv * lat1 + 2 * inv * t * controlLat + t * t * lat2,
      inv * inv * lon1 + 2 * inv * t * controlLon + t * t * lon2,
    ])
  }
  return points
}

const TILE_URL = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'

const MAX_ARCS = 14

export default function AttackMap({
  countries,
  arcs,
  className = 'h-[28rem]',
}: {
  countries: CountryStat[]
  arcs: AttackEvent[]
  className?: string
}) {
  const busiest = useMemo(() => Math.max(1, ...countries.map((c) => c.count)), [countries])
  const visibleArcs = useMemo(() => arcs.filter((a) => a.source_lat && a.destination_lat).slice(0, MAX_ARCS), [arcs])

  // Every arc converges on the defended estate; take it from the freshest event
  // and fall back to the seeded home region so the marker never disappears.
  const home: LatLng = visibleArcs.length
    ? [visibleArcs[0].destination_lat, visibleArcs[0].destination_lon]
    : [28.61, 77.21]

  return (
    <div className={`relative overflow-hidden rounded-lg border border-hairline ${className}`}>
      <MapContainer
        center={[22, 12]}
        zoom={2}
        minZoom={2}
        maxZoom={7}
        scrollWheelZoom
        worldCopyJump
        className="h-full w-full"
        style={{ background: '#04060c' }}
      >
        <TileLayer url={TILE_URL} attribution={TILE_ATTRIBUTION} />

        {/* Source countries, sized by volume, coloured by whether any were critical. */}
        {countries.map((country) => {
          const radius = 4 + Math.sqrt(country.count / busiest) * 13
          const colour = country.critical_count > 0 ? SEVERITY_HEX.critical : SEVERITY_HEX.high
          return (
            <CircleMarker
              key={country.country_code}
              center={[country.latitude, country.longitude]}
              radius={radius}
              pathOptions={{ color: colour, fillColor: colour, fillOpacity: 0.28, weight: 1.4 }}
            >
              <Tooltip direction="top" offset={[0, -4]}>
                <span className="font-medium">
                  {countryFlag(country.country_code)} {country.country_name}
                </span>
              </Tooltip>
              <Popup>
                <div className="space-y-1">
                  <p className="font-semibold text-white">
                    {countryFlag(country.country_code)} {country.country_name}
                  </p>
                  <p className="text-slate-300">
                    {country.count} attack{country.count === 1 ? '' : 's'}
                  </p>
                  {country.critical_count > 0 && (
                    <p style={{ color: SEVERITY_HEX.critical }}>{country.critical_count} critical</p>
                  )}
                </div>
              </Popup>
            </CircleMarker>
          )
        })}

        {/* Live arcs. Keyed by uid so a new event replays the draw animation. */}
        {visibleArcs.map((event, index) => {
          const colour = SEVERITY_HEX[event.severity]
          const freshness = 1 - index / MAX_ARCS
          return (
            <Polyline
              key={event.uid}
              positions={arcPoints(
                [event.source_lat, event.source_lon],
                [event.destination_lat, event.destination_lon],
              )}
              pathOptions={{
                color: colour,
                weight: index === 0 ? 2.4 : 1.5,
                opacity: 0.18 + freshness * 0.72,
                className: index < 4 ? 'attack-arc' : undefined,
              }}
            >
              <Popup>
                <div className="space-y-1">
                  <p className="font-semibold" style={{ color: colour }}>
                    {event.attack_type}
                  </p>
                  <p className="text-slate-300">
                    {countryFlag(event.source_country)} {event.source_country_name} →{' '}
                    {countryFlag(event.destination_country)} {event.destination_country_name}
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    {event.source_ip} → {event.destination_ip}:{event.destination_port}
                  </p>
                  <p className="text-[11px] text-slate-500">
                    {clockTime(event.detected_at)} · score {event.threat_score.toFixed(0)}
                  </p>
                </div>
              </Popup>
            </Polyline>
          )
        })}

        {/* The protected estate. */}
        <CircleMarker
          center={home}
          radius={7}
          pathOptions={{ color: '#22d3ee', fillColor: '#22d3ee', fillOpacity: 0.85, weight: 2 }}
        >
          <Tooltip direction="top" offset={[0, -4]} permanent>
            <span className="font-semibold">Protected estate</span>
          </Tooltip>
        </CircleMarker>
      </MapContainer>

      <div className="pointer-events-none absolute bottom-2 left-2 z-[400] flex flex-wrap gap-3 rounded-md border border-hairline bg-void/85 px-3 py-2 text-[10px] backdrop-blur">
        {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
          <span key={severity} className="flex items-center gap-1.5 uppercase tracking-wide text-slate-400">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_HEX[severity] }} />
            {severity}
          </span>
        ))}
      </div>
    </div>
  )
}
