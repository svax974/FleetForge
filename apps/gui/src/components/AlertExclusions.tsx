/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Exemptions d'alertes d'une machine — `alert_exclude` sur ses entrées.
 *
 * L'inventaire fait foi : on y écrit la liste de l'entrée choisie, puis
 * « Appliquer » rend les règles (`update-prometheus-alerts.yml`). Entre les
 * deux, l'exemption est enregistrée mais pas encore effective — d'où les deux
 * boutons distincts plutôt qu'un seul geste qui masquerait l'étape.
 */

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { X, Plus, Save, Play } from 'lucide-react'
import { setHostAlertExclusions, listAnsiblePlaybooks } from '../lib/api'
import { AnsibleHost, AlertRule, PlaybookLaunchConfig, AnsiblePlaybook } from '../types'

const APPLY_PLAYBOOK = 'update-prometheus-alerts'

interface AlertExclusionsProps {
  inventoryPath: string
  hosts: AnsibleHost[]
  rules: AlertRule[]
  onSaved: () => void
  onLaunchPlaybook: (config: PlaybookLaunchConfig) => void
}

export function AlertExclusions({ inventoryPath, hosts, rules, onSaved, onLaunchPlaybook }: AlertExclusionsProps) {
  const { t } = useTranslation()
  const [entry, setEntry] = useState<string>(hosts[0]?.name ?? '')
  const [alerts, setAlerts] = useState<string[]>([])
  const [toAdd, setToAdd] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const host = hosts.find((h: AnsibleHost) => h.name === entry)
  const original = useMemo((): string[] => host?.alert_exclude ?? [], [host])

  useEffect(() => {
    if (!hosts.some((h: AnsibleHost) => h.name === entry)) setEntry(hosts[0]?.name ?? '')
  }, [hosts, entry])

  useEffect(() => {
    setAlerts(original)
    setError(null)
    setSaved(false)
  }, [entry, original])

  const dirty = alerts.join(',') !== original.join(',')
  const candidates = rules.filter((r: AlertRule) => r.loaded && !alerts.includes(r.name))

  const add = (): void => {
    if (toAdd && !alerts.includes(toAdd)) setAlerts([...alerts, toAdd])
    setToAdd('')
  }

  const save = async (): Promise<void> => {
    setSaving(true)
    setError(null)
    try {
      await setHostAlertExclusions(inventoryPath, entry, alerts)
      setSaved(true)
      onSaved()
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setSaving(false)
    }
  }

  const apply = async (): Promise<void> => {
    setError(null)
    try {
      const playbook = (await listAnsiblePlaybooks()).find((p: AnsiblePlaybook) => p.name === APPLY_PLAYBOOK)
      if (!playbook) {
        setError(t('servers.alert_exclusions.no_playbook', { name: `${APPLY_PLAYBOOK}.yml` }))
        return
      }
      onLaunchPlaybook({
        id: crypto.randomUUID(),
        label: playbook.label || playbook.name,
        playbookPath: playbook.path,
        inventoryPath,
        limitHosts: null,
        displayHosts: [playbook.hosts || 'all'],
      })
      setSaved(false)
    } catch (err: unknown) {
      setError(String(err))
    }
  }

  if (hosts.length === 0) return null

  return (
    <div>
      <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">
        {t('servers.alert_exclusions.title')}
      </h4>

      {hosts.length > 1 && (
        <select
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          className="mb-2 w-full px-2 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 font-mono"
        >
          {hosts.map((h: AnsibleHost) => (
            <option key={h.name} value={h.name}>
              {h.name}{h.alert_exclude.length > 0 ? ` (${h.alert_exclude.length})` : ''}
            </option>
          ))}
        </select>
      )}

      <div className="flex flex-wrap gap-1.5 mb-2">
        {alerts.length === 0 && <span className="text-xs text-gray-600">{t('servers.alert_exclusions.none')}</span>}
        {alerts.map((a: string) => (
          <span
            key={a}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-amber-950/40 text-amber-200 border border-amber-800/50"
          >
            {a}
            <button
              onClick={() => setAlerts(alerts.filter((x: string) => x !== a))}
              className="text-amber-400 hover:text-amber-100"
              title={t('servers.alert_exclusions.remove')}
            >
              <X size={12} />
            </button>
          </span>
        ))}
      </div>

      <div className="flex gap-2 mb-2">
        <select
          value={toAdd}
          onChange={(e) => setToAdd(e.target.value)}
          className="flex-1 min-w-0 px-2 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200"
        >
          <option value="">{t('servers.alert_exclusions.pick')}</option>
          {candidates.map((r: AlertRule) => (
            <option key={r.name} value={r.name}>{r.name} — {r.group}</option>
          ))}
        </select>
        <button
          onClick={add}
          disabled={!toAdd}
          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200 disabled:opacity-40"
          title={t('servers.alert_exclusions.add')}
        >
          <Plus size={16} />
        </button>
      </div>

      <div className="flex gap-2">
        <button
          onClick={save}
          disabled={!dirty || saving}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary-600 text-white text-xs hover:bg-primary-500 disabled:opacity-40"
        >
          <Save size={14} /> {t('servers.alert_exclusions.save')}
        </button>
        <button
          onClick={apply}
          disabled={dirty}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-gray-700 text-gray-300 text-xs hover:border-gray-500 disabled:opacity-40"
          title={t('servers.alert_exclusions.apply_hint')}
        >
          <Play size={14} /> {t('servers.alert_exclusions.apply')}
        </button>
      </div>

      {saved && <p className="mt-2 text-xs text-green-400">{t('servers.alert_exclusions.saved')}</p>}
      {error && <p className="mt-2 text-xs text-red-300">{error}</p>}
    </div>
  )
}
