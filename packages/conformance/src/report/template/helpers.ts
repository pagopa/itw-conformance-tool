import type { Phase } from '../types.js';
import type { ComplianceTier } from './types.js';

// ─── String escaping ──────────────────────────────────────────────────────────

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// ─── Date formatting ──────────────────────────────────────────────────────────

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }

  return date.toLocaleString('it-IT', {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

export function formatGeneratedAt(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }

  return date.toLocaleString('it-IT', {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: '2-digit',
    second: '2-digit',
    year: 'numeric'
  });
}

// ─── Compliance resolvers ─────────────────────────────────────────────────────

export function resolveComplianceTier(pct: number): ComplianceTier {
  if (pct === 100) return 'passed';
  if (pct < 50) return 'failed';
  return 'partial';
}

/**
 * Resolves the conformance profile label from the session phase.
 * The phase is set authoritatively by the reporter at session creation time.
 */
export function resolveProfile(phase: Phase): string {
  if (phase === 'issuance') {
    return 'Wallet Provider (Issuance)';
  }

  if (phase === 'presentation') {
    return 'Wallet Provider (Presentation)';
  }

  if (phase === 'wallet-instance') {
    return 'Wallet Provider (Wallet Instance)';
  }

  if (phase === 'wallet-provider') {
    return 'Wallet Provider (Backend)';
  }

  return 'Wallet Provider';
}

export function resolveTierLabel(tier: ComplianceTier): string {
  if (tier === 'passed') return 'Conformità Completa';
  if (tier === 'failed') return 'Bassa Conformità';
  return 'Conformità Parziale';
}
