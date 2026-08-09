export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type EventStatus = 'active' | 'investigating' | 'mitigated' | 'resolved' | 'false_positive'
export type Role = 'admin' | 'analyst' | 'viewer'
export type SimStatus = 'running' | 'paused' | 'stopped'

export interface User {
  id: number
  email: string
  full_name: string
  role: Role
  is_active: boolean
  last_login_at: string | null
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: User
}

export interface Asset {
  id: number
  name: string
  hostname: string
  ip_address: string
  service: string
  port: number
  criticality: Severity
  owner: string
}

export interface AttackEvent {
  id: number
  uid: string
  detected_at: string
  attack_type: string
  name: string
  description: string
  severity: Severity
  status: EventStatus
  confidence: number
  threat_score: number
  recommended_action: string
  mitre_tactic: string
  mitre_technique: string
  source_ip: string
  source_port: number
  source_country: string
  source_country_name: string
  source_lat: number
  source_lon: number
  destination_ip: string
  destination_port: number
  destination_country: string
  destination_country_name: string
  destination_lat: number
  destination_lon: number
  protocol: string
  packet_count: number
  bytes_transferred: number
  response_time_ms: number
  blocked: boolean
  simulated: boolean
  indicators: string[]
  asset: Asset | null
}

export interface AIExplanation {
  why_detected: string
  potential_impact: string
  mitre_mapping: string
  recommended_mitigation: string
  future_prevention: string[]
  confidence: number
  generated_by: string
  created_at: string
}

export interface AttackEventDetail extends AttackEvent {
  raw_log: Record<string, unknown>
  explanation: AIExplanation | null
}

export interface EventPage {
  items: AttackEvent[]
  total: number
  page: number
  page_size: number
}

export interface NamedCount {
  name: string
  count: number
  extra: string
}

export interface DashboardStats {
  total_attacks: number
  active_attacks: number
  critical_attacks: number
  blocked_attacks: number
  threat_score: number
  attacks_last_hour: number
  attacks_previous_hour: number
  trend_pct: number
  avg_response_time_ms: number
  unique_attackers: number
  countries_involved: number
  by_severity: { severity: Severity; count: number }[]
  top_attack_types: NamedCount[]
  top_targeted_assets: NamedCount[]
  top_attackers: NamedCount[]
  top_targeted_services: NamedCount[]
}

export interface TimeBucket {
  timestamp: string
  count: number
  critical: number
  high: number
  blocked: number
  threat_score: number
  avg_response_ms: number
}

export interface CountryStat {
  country_code: string
  country_name: string
  latitude: number
  longitude: number
  count: number
  critical_count: number
}

export interface DetectionRule {
  id: number
  key: string
  name: string
  attack_type: string
  description: string
  severity: Severity
  confidence: number
  base_score: number
  mitre_tactic: string
  mitre_technique: string
  recommended_action: string
  enabled: boolean
  hit_count: number
  updated_at: string
}

export interface Notification {
  id: number
  event_id: number | null
  title: string
  message: string
  severity: Severity
  is_read: boolean
  created_at: string
}

export interface ThreatActor {
  id: number
  ip_address: string
  country_code: string
  country_name: string
  label: string
  event_count: number
  threat_score: number
  is_blocked: boolean
  tags: string[]
  first_seen: string
  last_seen: string
}

export interface ScenarioInfo {
  key: string
  name: string
  description: string
  expected_detection: string
}

export interface SimulationConfig {
  scenarios: string[]
  source_countries: string[]
  events_per_minute: number
  randomize_ips: boolean
  repeat: boolean
}

export interface SimulationState {
  status: SimStatus
  config: SimulationConfig
  events_generated: number
  detections: number
  started_at: string | null
  started_by: string | null
}

export interface CountryOption {
  code: string
  name: string
  latitude: number
  longitude: number
}

export interface AiStatus {
  live_model_available: boolean
  model: string
  detail: string
}

export interface LiveAttackTarget {
  username: string
  display_name: string
  is_defaced: boolean
  is_breached: boolean
  failed_logins: number
}
export interface LiveCatalog {
  attacks: { key: string; label: string }[]
  targets: LiveAttackTarget[]
  target_base_url: string
}
export interface LiveStartConfig {
  attacks: string[]
  target_username: string
  attacks_per_minute: number
  source_country?: string | null
  repeat: boolean
}
export interface LiveState {
  status: SimStatus
  attacks: string[]
  target_username: string
  attacks_per_minute: number
  source_country: string | null
  repeat: boolean
  started_by: string | null
  started_at: string | null
  requests_sent: number
  attacks_launched: number
  target_base_url: string
}
