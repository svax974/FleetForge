/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useState, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Package, Server, RefreshCw, ExternalLink, Plus, X, AlertCircle, Trash2, ShieldAlert } from 'lucide-react'
import {
  getServerServices, getServerCurrentServices,
  addManualService, getSelectedInventory, getInventoryGroups,
  getAvailableServiceNames, getUninstallRoles,
} from '../lib/api'
import { ServerService, ServerServiceState, AnsibleHost, AnsibleGroup, AnsibleRole, DeployLaunchConfig } from '../types'
import { View } from '../App'
import AnsibleDeployModal from './AnsibleDeployModal'

interface ServicesViewProps {
  onNavigate?: (view: View, runId?: number) => void
  onLaunchDeploy: (config: DeployLaunchConfig) => void
}

type Tab = 'current' | 'audit'

interface HostOption {
  serverId: number    // 0 for inventory-only hosts not in servers table
  serverName: string
  label: string
}

const ACTION_COLORS: Record<string, string> = {
  install:  'bg-green-900/40 text-green-300 border border-green-700/50',
  remove:   'bg-red-900/40 text-red-300 border border-red-700/50',
  purge:    'bg-red-900/60 text-red-200 border border-red-700/50',
  update:   'bg-blue-900/40 text-blue-300 border border-blue-700/50',
  security: 'bg-purple-900/40 text-purple-300 border border-purple-700/50',
}

const SOURCE_COLORS: Record<string, string> = {
  ansible: 'bg-violet-900/40 text-violet-300 border border-violet-700/50',
  ssh:     'bg-gray-800 text-gray-400 border border-gray-600',
  manual:  'bg-amber-900/40 text-amber-300 border border-amber-700/50',
}

function ActionBadge({ action, t }: { action: string; t: (k: string) => string }) {
  const cls = ACTION_COLORS[action] ?? 'bg-gray-800 text-gray-300'
  const label = t(`services.action_${action}`) !== `services.action_${action}`
    ? t(`services.action_${action}`)
    : action
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{label}</span>
}

function SourceBadge({ source, t }: { source: string; t: (k: string) => string }) {
  const cls = SOURCE_COLORS[source] ?? 'bg-gray-800 text-gray-400'
  const label = t(`services.source_${source}`) !== `services.source_${source}`
    ? t(`services.source_${source}`)
    : source
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{label}</span>
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// Flatten all hosts from a nested group tree
function flattenHosts(groups: AnsibleGroup[]): AnsibleHost[] {
  const hosts: AnsibleHost[] = []
  const seen = new Set<string>()
  function walk(g: AnsibleGroup) {
    for (const h of g.hosts) {
      if (!seen.has(h.name)) { seen.add(h.name); hosts.push(h) }
    }
    for (const child of g.children) walk(child)
  }
  groups.forEach(walk)
  return hosts
}

// Combobox with filtering suggestions
function ServiceCombobox({ value, onChange, suggestions, placeholder }: {
  value: string
  onChange: (v: string) => void
  suggestions: string[]
  placeholder: string
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const filtered = useMemo(() => {
    if (!value.trim()) return suggestions
    const q = value.toLowerCase()
    return suggestions.filter(s => s.toLowerCase().includes(q))
  }, [value, suggestions])

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div ref={ref} className="relative">
      <input
        type="text"
        value={value}
        onChange={(e) => { onChange(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        placeholder={placeholder}
        autoComplete="off"
        className="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 placeholder:text-gray-600"
      />
      {open && filtered.length > 0 && (
        <ul className="absolute z-20 w-full mt-1 bg-gray-900 border border-gray-700 rounded-lg shadow-xl overflow-hidden max-h-48 overflow-y-auto">
          {filtered.map((s) => (
            <li
              key={s}
              onMouseDown={(e) => { e.preventDefault(); onChange(s); setOpen(false) }}
              className={`px-3 py-2 text-sm cursor-pointer font-mono transition-colors ${
                s === value
                  ? 'bg-primary-700 text-white'
                  : 'text-gray-300 hover:bg-gray-700'
              }`}
            >
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function ServicesView({ onNavigate, onLaunchDeploy }: ServicesViewProps) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<Tab>('current')
  const [currentServices, setCurrentServices] = useState<ServerServiceState[]>([])
  const [auditServices, setAuditServices] = useState<ServerService[]>([])
  const [hostOptions, setHostOptions] = useState<HostOption[]>([])
  const [serviceSuggestions, setServiceSuggestions] = useState<string[]>([])
  /** service → action → rôle, résolu par le cœur. */
  const [uninstallRoles, setUninstallRoles] = useState<Record<string, Record<string, AnsibleRole>>>({})
  const [loading, setLoading] = useState(false)

  // Uninstall modal — pre-filled with the matching `<service>-remove`/`<service>-purge` role
  const [uninstallRole, setUninstallRole] = useState<AnsibleRole | null>(null)
  const [uninstallHost, setUninstallHost] = useState<string>('')

  const [filterServerName, setFilterServerName] = useState<string>('')
  const [filterService, setFilterService] = useState('')
  const [filterStatus, setFilterStatus] = useState<'all' | 'success' | 'failed'>('all')

  // Manual entry modal
  const [showManualModal, setShowManualModal] = useState(false)
  const [manualHost, setManualHost] = useState<HostOption | null>(null)
  const [manualServiceName, setManualServiceName] = useState('')
  const [manualAction, setManualAction] = useState('install')
  const [manualNotes, setManualNotes] = useState('')
  const [manualSaving, setManualSaving] = useState(false)
  const [manualError, setManualError] = useState<string | null>(null)

  const handleAddManual = async (): Promise<void> => {
    if (!manualHost || !manualServiceName.trim()) return
    setManualSaving(true)
    setManualError(null)
    try {
      // `serverId` a disparu : il valait toujours 0, la table `servers` étant
      // morte. C'est le nom d'hôte d'inventaire qui identifie la cible.
      await addManualService(
        manualHost.serverName,
        manualServiceName.trim(),
        manualAction,
        manualNotes.trim() || undefined
      )
      setShowManualModal(false)
      setManualHost(null)
      setManualServiceName('')
      setManualAction('install')
      setManualNotes('')
      load()
    } catch (err) {
      setManualError(String(err))
    } finally {
      setManualSaving(false)
    }
  }

  const load = async (): Promise<void> => {
    setLoading(true)
    try {
      const [svcStates, audits] = await Promise.all([
        getServerCurrentServices(),
        getServerServices(),
      ])
      setCurrentServices(svcStates)
      setAuditServices(audits)

      // Build host list from Ansible inventory
      const opts: HostOption[] = []
      const invPath = await getSelectedInventory().catch(() => '')
      if (invPath) {
        const groups = await getInventoryGroups(invPath).catch(() => [] as AnsibleGroup[])
        const inventoryHosts = flattenHosts(groups)
        for (const h of inventoryHosts) {
          opts.push({ serverId: 0, serverName: h.name, label: h.name })
        }
      }
      opts.sort((a, b) => a.serverName.localeCompare(b.serverName))
      setHostOptions(opts)

      // Build service name suggestions from available playbooks (dynamic catalog)
      const catalogNames = await getAvailableServiceNames().catch(() => [] as string[])
      // Also include already tracked services for completeness
      const trackedNames = new Set<string>()
      for (const s of audits) trackedNames.add(s.service_name)
      for (const s of svcStates) trackedNames.add(s.service_name)
      const allNames = new Set([...catalogNames, ...trackedNames])
      setServiceSuggestions([...allNames].sort())

      // Le cœur résout quel rôle désinstalle quoi : reconstruire
      // `<service>-<action>` ici échouait sur tout service renommé.
      const tracked = [...trackedNames]
      setUninstallRoles(
        tracked.length > 0
          ? await getUninstallRoles(tracked, ['remove', 'purge']).catch(() => ({}))
          : {},
      )
    } catch {
      // errors surfaced via empty state
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // La résolution vient du cœur, qui connaît la table de désambiguïsation et
  // ses alias : « nginx-proxy » + remove → `proxy-remove`, qu'aucune
  // reconstruction naïve du nom ne trouvait.
  const findUninstallRole = (serviceName: string, action: 'remove' | 'purge'): AnsibleRole | null =>
    uninstallRoles[serviceName]?.[action] ?? null

  const openUninstall = (serviceName: string, serverName: string, action: 'remove' | 'purge'): void => {
    const role = findUninstallRole(serviceName, action)
    if (!role) return
    setUninstallRole(role)
    setUninstallHost(serverName)
  }

  const handleUninstallLaunch = (config: DeployLaunchConfig): void => {
    onLaunchDeploy(config)
    load()
  }

  const filteredCurrent = useMemo((): ServerServiceState[] => {
    return currentServices.filter((s: ServerServiceState) => {
      if (filterServerName && s.server_name !== filterServerName) return false
      if (filterService && !s.service_name.toLowerCase().includes(filterService.toLowerCase())) return false
      return true
    })
  }, [currentServices, filterServerName, filterService])

  const filteredAudit = useMemo((): ServerService[] => {
    return auditServices.filter((s: ServerService) => {
      if (filterServerName && s.server_name !== filterServerName) return false
      if (filterService && !s.service_name.toLowerCase().includes(filterService.toLowerCase())) return false
      if (filterStatus !== 'all' && s.status !== filterStatus) return false
      return true
    })
  }, [auditServices, filterServerName, filterService, filterStatus])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Package className="w-7 h-7 text-primary-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">{t('services.title')}</h1>
            <p className="text-sm text-gray-400">{t('services.subtitle')}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowManualModal(true)}
            className="flex items-center gap-2 px-3 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('services.add_manual')}
          </button>
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Manual entry modal */}
      {showManualModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl shadow-xl w-full max-w-md border border-gray-700">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-bold text-gray-100">{t('services.add_manual_title')}</h2>
              <button onClick={() => setShowManualModal(false)} className="p-1 hover:bg-gray-700 rounded">
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>
            <div className="px-6 py-5 space-y-4">
              {manualError && (
                <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 text-red-400 rounded-lg px-3 py-2 text-sm">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {manualError}
                </div>
              )}

              {/* Server */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">{t('services.col_server')}</label>
                <select
                  value={manualHost?.serverName ?? ''}
                  onChange={(e) => {
                    const opt = hostOptions.find((h) => h.serverName === e.target.value) ?? null
                    setManualHost(opt)
                  }}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg text-sm focus:ring-2 focus:ring-primary-500"
                >
                  <option value="">{t('services.select_server')}</option>
                  {hostOptions.map((h) => (
                    <option key={`${h.serverId}-${h.serverName}`} value={h.serverName}>
                      {h.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Service name with autocomplete */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">{t('services.col_service')}</label>
                <ServiceCombobox
                  value={manualServiceName}
                  onChange={setManualServiceName}
                  suggestions={serviceSuggestions}
                  placeholder={t('services.service_name_placeholder')}
                />
              </div>

              {/* Action */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">{t('services.col_action')}</label>
                <select
                  value={manualAction}
                  onChange={(e) => setManualAction(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg text-sm focus:ring-2 focus:ring-primary-500"
                >
                  {['install', 'remove', 'purge', 'update', 'security'].map((a) => (
                    <option key={a} value={a}>{t(`services.action_${a}`)}</option>
                  ))}
                </select>
              </div>

              {/* Notes */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  {t('services.notes')} <span className="text-gray-500 font-normal">(optionnel)</span>
                </label>
                <textarea
                  value={manualNotes}
                  onChange={(e) => setManualNotes(e.target.value)}
                  rows={2}
                  placeholder={t('services.notes_placeholder')}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 placeholder:text-gray-600 resize-none"
                />
              </div>
            </div>
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-700">
              <button
                onClick={() => setShowManualModal(false)}
                className="px-4 py-2 text-sm text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={handleAddManual}
                disabled={!manualHost || !manualServiceName.trim() || manualSaving}
                className="px-4 py-2 text-sm text-white bg-primary-600 hover:bg-primary-700 rounded-lg disabled:opacity-40"
              >
                {manualSaving ? t('common.saving') : t('services.add_manual_confirm')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Uninstall modal — reuses the same deploy flow as RolesView, pre-selected */}
      {uninstallRole && (
        <AnsibleDeployModal
          role={uninstallRole}
          initialHosts={[uninstallHost]}
          onClose={() => setUninstallRole(null)}
          onLaunch={handleUninstallLaunch}
        />
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 p-1 rounded-lg w-fit">
        {(['current', 'audit'] as const).map((tabId: Tab) => (
          <button
            key={tabId}
            onClick={() => setTab(tabId)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === tabId
                ? 'bg-primary-600 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {t(`services.tab_${tabId === 'current' ? 'current' : 'audit'}`)}
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-gray-500" />
          <select
            value={filterServerName}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilterServerName(e.target.value)}
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:ring-1 focus:ring-primary-500"
          >
            <option value="">{t('services.filter_server')}: {t('services.filter_all')}</option>
            {hostOptions.map((h) => (
              <option key={h.serverName} value={h.serverName}>{h.label}</option>
            ))}
          </select>
        </div>

        <input
          type="text"
          value={filterService}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilterService(e.target.value)}
          placeholder={t('services.filter_service')}
          className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:ring-1 focus:ring-primary-500 w-44"
        />

        {tab === 'audit' && (
          <select
            value={filterStatus}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
              setFilterStatus(e.target.value as 'all' | 'success' | 'failed')
            }
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:ring-1 focus:ring-primary-500"
          >
            <option value="all">{t('services.filter_status')}: {t('services.filter_all')}</option>
            <option value="success">{t('services.status_success')}</option>
            <option value="failed">{t('services.status_failed')}</option>
          </select>
        )}
      </div>

      {/* Current State Tab */}
      {tab === 'current' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          {filteredCurrent.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <Package className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="font-medium">{t('services.no_services')}</p>
              <p className="text-sm mt-1 text-gray-600">{t('services.no_services_desc')}</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">
                  <th className="text-left px-4 py-3">{t('services.col_server')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_service')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_action')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_source')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_date')}</th>
                  <th className="text-right px-4 py-3">{t('services.col_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredCurrent.map((svc: ServerServiceState, i: number) => {
                  const removeRole = findUninstallRole(svc.service_name, 'remove')
                  const purgeRole = findUninstallRole(svc.service_name, 'purge')
                  return (
                  <tr
                    key={`${svc.server_id}-${svc.service_name}`}
                    className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${
                      i % 2 === 0 ? '' : 'bg-gray-900/50'
                    }`}
                  >
                    <td className="px-4 py-3 text-gray-200 font-medium">{svc.server_name}</td>
                    <td className="px-4 py-3 text-white font-mono text-xs">{svc.service_name}</td>
                    <td className="px-4 py-3">
                      <ActionBadge action={svc.last_action} t={t} />
                    </td>
                    <td className="px-4 py-3">
                      <SourceBadge source={svc.last_source} t={t} />
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{formatDate(svc.installed_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1.5">
                        {removeRole && (
                          <button
                            onClick={() => openUninstall(svc.service_name, svc.server_name, 'remove')}
                            title={t('services.uninstall_remove')}
                            className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {purgeRole && (
                          <button
                            onClick={() => openUninstall(svc.service_name, svc.server_name, 'purge')}
                            title={t('services.uninstall_purge')}
                            className="p-1.5 text-gray-500 hover:text-red-500 hover:bg-red-900/20 rounded transition-colors"
                          >
                            <ShieldAlert className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Audit Log Tab */}
      {tab === 'audit' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          {filteredAudit.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <Package className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="font-medium">{t('services.no_services')}</p>
              <p className="text-sm mt-1 text-gray-600">{t('services.no_services_desc')}</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">
                  <th className="text-left px-4 py-3">{t('services.col_server')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_service')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_role')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_action')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_source')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_status')}</th>
                  <th className="text-left px-4 py-3">{t('services.col_date')}</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {filteredAudit.map((svc: ServerService, i: number) => (
                  <tr
                    key={svc.id}
                    className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${
                      i % 2 === 0 ? '' : 'bg-gray-900/50'
                    }`}
                  >
                    <td className="px-4 py-3 text-gray-200 font-medium">{svc.server_name}</td>
                    <td className="px-4 py-3 text-white font-mono text-xs">{svc.service_name}</td>
                    <td className="px-4 py-3 text-gray-500 font-mono text-xs">{svc.role_name ?? '—'}</td>
                    <td className="px-4 py-3">
                      <ActionBadge action={svc.action} t={t} />
                    </td>
                    <td className="px-4 py-3">
                      <SourceBadge source={svc.source} t={t} />
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        svc.status === 'success'
                          ? 'bg-green-900/40 text-green-300 border border-green-700/50'
                          : 'bg-orange-900/40 text-orange-300 border border-orange-700/50'
                      }`}>
                        {t(`services.status_${svc.status}`)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{formatDate(svc.executed_at)}</td>
                    <td className="px-4 py-3">
                      {svc.ansible_run_id != null && onNavigate && (
                        <button
                          onClick={() => onNavigate('ansible-runs')}
                          title={t('services.see_run')}
                          className="text-gray-600 hover:text-primary-400 transition-colors"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
