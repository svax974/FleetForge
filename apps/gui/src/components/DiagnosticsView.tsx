/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Vue Diagnostics — la cohérence du parc, rendue visible.
 *
 * Chaque règle correspond à une panne silencieuse déjà payée : Prometheus
 * installé après les services et ses `file_sd` restés vides, web3c huit
 * semaines sans Alertmanager, le job `node-btc` vide depuis toujours. Le point
 * commun de ces pannes est qu'un parc en défaut ressemble exactement à un parc
 * sain.
 */

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, RefreshCw, AlertCircle, AlertTriangle, Info } from 'lucide-react'
import { getDiagnostics } from '../lib/api'
import { Finding, Severity } from '../types'

interface DiagnosticsViewProps {
  selectedInventory: string
  configMissing: boolean
}

const SEVERITY_STYLE: Record<Severity, { row: string; badge: string; icon: typeof AlertCircle }> = {
  error:   { row: 'border-red-800/50 bg-red-950/30',     badge: 'text-red-300',   icon: AlertCircle },
  warning: { row: 'border-amber-800/40 bg-amber-950/20', badge: 'text-amber-300', icon: AlertTriangle },
  info:    { row: 'border-gray-700 bg-gray-900/40',      badge: 'text-primary-300', icon: Info },
}

function subjectLabel(f: Finding, t: (k: string) => string): string {
  switch (f.subject.kind) {
    case 'host': return `${t('diagnostics.subject_host')} ${f.subject.id}`
    case 'server': return `${t('diagnostics.subject_server')} ${f.subject.id}`
    case 'rolefamily': return `${t('diagnostics.subject_family')} ${f.subject.id}`
    case 'fleet': return `${t('diagnostics.subject_fleet')} ${f.subject.id}`
  }
}

export default function DiagnosticsView({ selectedInventory, configMissing }: DiagnosticsViewProps) {
  const { t } = useTranslation()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')

  const load = async (): Promise<void> => {
    if (!selectedInventory) {
      setFindings([])
      return
    }
    setLoading(true)
    setError(null)
    try {
      setFindings(await getDiagnostics(selectedInventory))
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [selectedInventory])

  const counts = useMemo(() => ({
    error: findings.filter((f) => f.severity === 'error').length,
    warning: findings.filter((f) => f.severity === 'warning').length,
    info: findings.filter((f) => f.severity === 'info').length,
  }), [findings])

  const visible = useMemo((): Finding[] => (
    severityFilter === 'all' ? findings : findings.filter((f) => f.severity === severityFilter)
  ), [findings, severityFilter])

  /** Regroupé par règle : dix machines non scrutées sont UN problème, pas dix. */
  const grouped = useMemo((): [string, Finding[]][] => {
    const map = new Map<string, Finding[]>()
    for (const f of visible) {
      const list = map.get(f.rule)
      if (list) list.push(f)
      else map.set(f.rule, [f])
    }
    return [...map.entries()]
  }, [visible])

  if (configMissing) {
    return <div className="p-8 text-gray-500">{t('common.config_missing')}</div>
  }
  if (!selectedInventory) {
    return <div className="p-8 text-gray-500">{t('inventory.no_inventory_selected')}</div>
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl text-gray-100 flex items-center gap-2">
            <ShieldCheck size={20} className="text-primary-400" />
            {t('diagnostics.title')}
          </h2>
          <p className="text-sm text-gray-500 mt-1">{t('diagnostics.subtitle')}</p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="p-2 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 disabled:opacity-40"
          title={t('common.refresh')}
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="flex gap-2 mb-6">
        {([
          ['all', findings.length, 'text-gray-300'],
          ['error', counts.error, 'text-red-300'],
          ['warning', counts.warning, 'text-amber-300'],
          ['info', counts.info, 'text-primary-300'],
        ] as [Severity | 'all', number, string][]).map(([key, count, colour]) => (
          <button
            key={key}
            onClick={() => setSeverityFilter(key)}
            className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
              severityFilter === key
                ? 'border-primary-600 bg-primary-950/40 text-gray-100'
                : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            <span className={severityFilter === key ? '' : colour}>{count}</span>
            <span className="ml-2 text-gray-500">{t(`diagnostics.sev_${key}`)}</span>
          </button>
        ))}
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-800/50 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      )}

      {!loading && findings.length === 0 && (
        <div className="rounded-xl border border-green-800/40 bg-green-950/20 px-5 py-6 text-green-300">
          {t('diagnostics.all_clear')}
        </div>
      )}

      <div className="space-y-4">
        {grouped.map(([rule, items]: [string, Finding[]]) => {
          const style = SEVERITY_STYLE[items[0].severity]
          const Icon = style.icon
          return (
            <section key={rule} className={`rounded-xl border ${style.row}`}>
              <header className="flex items-center gap-2 px-4 py-3 border-b border-gray-800/60">
                <Icon size={15} className={style.badge} />
                <span className="font-mono text-sm text-gray-200">{rule}</span>
                <span className="text-xs text-gray-500">
                  {items.length} {t(items.length > 1 ? 'diagnostics.occurrences' : 'diagnostics.occurrence')}
                </span>
              </header>
              <ul className="divide-y divide-gray-800/50">
                {items.map((f: Finding, i: number) => (
                  <li key={`${rule}-${i}`} className="px-4 py-3">
                    <p className="text-sm text-gray-200">{f.message}</p>
                    <p className="text-xs text-gray-600 mt-1 font-mono">{subjectLabel(f, t)}</p>
                  </li>
                ))}
              </ul>
            </section>
          )
        })}
      </div>
    </div>
  )
}
