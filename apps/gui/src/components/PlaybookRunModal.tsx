/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  X,
  Loader,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  BookOpen,
} from 'lucide-react'
import {
  getSelectedInventory,
  getInventoryGroups,
  checkAnsibleAvailable,
} from '../lib/api'
import { AnsiblePlaybook, AnsibleGroup, AnsibleHost, PlaybookLaunchConfig } from '../types'

interface PlaybookRunModalProps {
  playbook: AnsiblePlaybook
  /** Hôtes préchargés : le playbook est alors limité à eux, comme `p` dans le TUI. */
  initialHosts?: string[]
  onClose: () => void
  onLaunch: (config: PlaybookLaunchConfig) => void
}

interface ExtraVar {
  key: string
  value: string
}

type HostsMode = 'all' | 'specific'

function GroupBlock({
  group,
  selectedHosts,
  onToggleHost,
}: {
  group: AnsibleGroup
  selectedHosts: Set<string>
  onToggleHost: (host: AnsibleHost) => void
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(true)

  const allSelected =
    group.hosts.length > 0 && group.hosts.every((h) => selectedHosts.has(h.name))
  const someSelected =
    group.hosts.some((h) => selectedHosts.has(h.name)) && !allSelected

  const handleSelectAll = () => {
    if (allSelected) {
      group.hosts.forEach((h) => { if (selectedHosts.has(h.name)) onToggleHost(h) })
    } else {
      group.hosts.forEach((h) => { if (!selectedHosts.has(h.name)) onToggleHost(h) })
    }
  }

  if (group.hosts.length === 0 && group.children.length === 0) return null

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-gray-700 border-b border-gray-600">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-1.5 text-sm font-medium text-gray-300 hover:text-gray-100"
        >
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          {group.name}
          <span className="text-xs text-gray-500 font-normal">({group.hosts.length})</span>
        </button>
        {group.hosts.length > 0 && (
          <button
            onClick={handleSelectAll}
            className="text-xs text-primary-400 hover:text-primary-300 font-medium"
          >
            {allSelected || someSelected
              ? t('playbook_run.deselect_all')
              : t('playbook_run.select_all')}
          </button>
        )}
      </div>
      {expanded && (
        <div className="divide-y divide-gray-700">
          {group.hosts.map((host) => (
            <label
              key={host.name}
              className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-700/50 transition-colors"
            >
              <input
                type="checkbox"
                checked={selectedHosts.has(host.name)}
                onChange={() => onToggleHost(host)}
                className="w-4 h-4 text-primary-600 border-gray-600 rounded focus:ring-primary-500 bg-gray-900"
              />
              <span className="text-sm font-medium text-gray-100">{host.name}</span>
              {host.ansible_host && (
                <span className="text-xs text-gray-500 font-mono ml-auto">{host.ansible_host}</span>
              )}
            </label>
          ))}
          {group.children.map((child) => (
            <div key={child.name} className="pl-4">
              <GroupBlock group={child} selectedHosts={selectedHosts} onToggleHost={onToggleHost} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function PlaybookRunModal({ playbook, initialHosts, onClose, onLaunch }: PlaybookRunModalProps) {
  const { t } = useTranslation()

  const [loadingInit, setLoadingInit] = useState(true)
  const [initError, setInitError] = useState<string | null>(null)
  const [ansibleAvailable, setAnsibleAvailable] = useState(true)
  const [inventoryPath, setInventoryPath] = useState('')
  const [groups, setGroups] = useState<AnsibleGroup[]>([])

  const [hostsMode, setHostsMode] = useState<HostsMode>(initialHosts?.length ? 'specific' : 'all')
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set(initialHosts ?? []))

  const [extraVars, setExtraVars] = useState<ExtraVar[]>([])
  const [newVarKey, setNewVarKey] = useState('')
  const [newVarValue, setNewVarValue] = useState('')

  useEffect(() => {
    initModal()
  }, [])

  const initModal = async () => {
    setLoadingInit(true)
    setInitError(null)
    try {
      const [available, invPath] = await Promise.all([
        checkAnsibleAvailable(),
        getSelectedInventory(),
      ])
      setAnsibleAvailable(available)
      setInventoryPath(invPath)
      if (invPath) {
        const grps = await getInventoryGroups(invPath)
        setGroups(grps)
      }
    } catch {
      setInitError(t('playbook_run.run_failed'))
    } finally {
      setLoadingInit(false)
    }
  }

  const handleToggleHost = (host: AnsibleHost) => {
    setSelectedHosts((prev) => {
      const next = new Set(prev)
      if (next.has(host.name)) next.delete(host.name)
      else next.add(host.name)
      return next
    })
  }

  const handleAddVar = () => {
    if (!newVarKey.trim()) return
    setExtraVars((prev) => [...prev, { key: newVarKey.trim(), value: newVarValue.trim() }])
    setNewVarKey('')
    setNewVarValue('')
  }

  const handleRemoveVar = (index: number) => {
    setExtraVars((prev) => prev.filter((_, i) => i !== index))
  }

  const handleRun = () => {
    if (!inventoryPath) return
    if (hostsMode === 'specific' && selectedHosts.size === 0) return

    const limitHosts = hostsMode === 'specific' ? Array.from(selectedHosts) : null
    const varsMap: Record<string, string> = {}
    extraVars.forEach((v) => { if (v.key) varsMap[v.key] = v.value })

    const displayHosts = hostsMode === 'specific'
      ? Array.from(selectedHosts)
      : [playbook.hosts || 'all']

    const config: PlaybookLaunchConfig = {
      id: crypto.randomUUID(),
      label: playbook.label || playbook.name,
      playbookPath: playbook.path,
      inventoryPath,
      limitHosts,
      displayHosts,
      extraVars: Object.keys(varsMap).length > 0 ? varsMap : undefined,
    }

    onLaunch(config)
    onClose()
  }

  const canRun =
    ansibleAvailable &&
    !!inventoryPath &&
    (hostsMode === 'all' || selectedHosts.size > 0)

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl shadow-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto border border-gray-700">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <div className="flex items-center gap-3">
            <BookOpen className="w-5 h-5 text-indigo-400" />
            <div>
              <h2 className="text-xl font-bold text-gray-100">{t('playbook_run.title')}</h2>
              <p className="text-xs text-gray-500 font-mono">{playbook.name}.yml</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {loadingInit && (
            <div className="flex items-center gap-2 text-gray-400 text-sm">
              <Loader className="w-4 h-4 animate-spin" />
              {t('common.loading')}
            </div>
          )}

          {initError && (
            <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 text-red-400 rounded-lg px-4 py-3 text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {initError}
            </div>
          )}

          {!loadingInit && !ansibleAvailable && (
            <div className="flex items-center gap-2 bg-yellow-900/30 border border-yellow-700 text-yellow-400 rounded-lg px-4 py-3 text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {t('playbook_run.run_failed')}
            </div>
          )}

          {!loadingInit && (
            <>
              {/* Playbook info */}
              {playbook.description && (
                <p className="text-sm text-gray-400">{playbook.description}</p>
              )}

              {/* Inventory */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-1">
                  {t('playbook_run.inventory_label')}
                </p>
                <p className="text-sm text-gray-400 font-mono bg-gray-900 border border-gray-700 rounded px-3 py-2">
                  {inventoryPath || (
                    <span className="text-gray-600 italic">{t('playbook_run.no_inventory')}</span>
                  )}
                </p>
                {!inventoryPath && (
                  <p className="mt-1 text-xs text-amber-400">{t('playbook_run.select_inventory_first')}</p>
                )}
              </div>

              {/* Hosts mode */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-3">
                  {t('playbook_run.hosts_mode_label')}
                </p>
                <div className="space-y-2">
                  <label
                    className={`flex items-start gap-3 p-4 border rounded-lg cursor-pointer transition-colors ${
                      hostsMode === 'all'
                        ? 'border-primary-500 bg-primary-900/30'
                        : 'border-gray-700 hover:border-gray-600 hover:bg-gray-700/30'
                    }`}
                  >
                    <input
                      type="radio"
                      name="hostsMode"
                      value="all"
                      checked={hostsMode === 'all'}
                      onChange={() => setHostsMode('all')}
                      className="mt-0.5 w-4 h-4 text-primary-600 border-gray-600 focus:ring-primary-500 bg-gray-900"
                    />
                    <div>
                      <p className="font-medium text-gray-100 text-sm">{t('playbook_run.mode_all')}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {t('playbook_run.mode_all_desc', { hosts: playbook.hosts || 'all' })}
                      </p>
                    </div>
                  </label>

                  <label
                    className={`flex items-start gap-3 p-4 border rounded-lg cursor-pointer transition-colors ${
                      hostsMode === 'specific'
                        ? 'border-primary-500 bg-primary-900/30'
                        : 'border-gray-700 hover:border-gray-600 hover:bg-gray-700/30'
                    }`}
                  >
                    <input
                      type="radio"
                      name="hostsMode"
                      value="specific"
                      checked={hostsMode === 'specific'}
                      onChange={() => setHostsMode('specific')}
                      className="mt-0.5 w-4 h-4 text-primary-600 border-gray-600 focus:ring-primary-500 bg-gray-900"
                    />
                    <div>
                      <p className="font-medium text-gray-100 text-sm">{t('playbook_run.mode_specific')}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{t('playbook_run.mode_specific_desc')}</p>
                    </div>
                  </label>
                </div>
              </div>

              {/* Host list (only when mode = specific) */}
              {hostsMode === 'specific' && (
                <div>
                  <p className="text-sm font-medium text-gray-300 mb-2">
                    {t('playbook_run.select_hosts')}{' '}
                    {selectedHosts.size > 0 && (
                      <span className="text-primary-400">({selectedHosts.size})</span>
                    )}
                  </p>
                  {groups.length === 0 ? (
                    <p className="text-sm text-gray-500 italic">{t('playbook_run.no_inventory')}</p>
                  ) : (
                    <div className="space-y-2">
                      {groups.map((group) => (
                        <GroupBlock
                          key={group.name}
                          group={group}
                          selectedHosts={selectedHosts}
                          onToggleHost={handleToggleHost}
                        />
                      ))}
                    </div>
                  )}
                  {selectedHosts.size === 0 && groups.length > 0 && (
                    <p className="mt-2 text-xs text-red-400">{t('playbook_run.no_hosts_selected')}</p>
                  )}
                </div>
              )}

              {/* Extra variables */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-2">
                  {t('playbook_run.extra_vars')}{' '}
                  <span className="text-gray-500 font-normal">(optionnel)</span>
                </p>
                <div className="flex items-center gap-2 mb-2">
                  <input
                    type="text"
                    placeholder={t('playbook_run.var_name')}
                    value={newVarKey}
                    onChange={(e) => setNewVarKey(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddVar()}
                    className="flex-1 text-sm border border-gray-600 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500 bg-gray-900 text-gray-100 placeholder:text-gray-600"
                  />
                  <input
                    type="text"
                    placeholder={t('playbook_run.var_value')}
                    value={newVarValue}
                    onChange={(e) => setNewVarValue(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddVar()}
                    className="flex-1 text-sm border border-gray-600 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500 bg-gray-900 text-gray-100 placeholder:text-gray-600"
                  />
                  <button
                    onClick={handleAddVar}
                    disabled={!newVarKey.trim()}
                    className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs font-medium rounded-md transition-colors disabled:opacity-40"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    {t('playbook_run.add_variable')}
                  </button>
                </div>
                {extraVars.length > 0 && (
                  <ul className="space-y-1">
                    {extraVars.map((v, i) => (
                      <li
                        key={i}
                        className="flex items-center justify-between text-sm bg-gray-900 border border-gray-700 rounded px-3 py-1.5"
                      >
                        <span>
                          <span className="font-mono text-gray-300">{v.key}</span>
                          <span className="text-gray-500 mx-1">=</span>
                          <span className="font-mono text-gray-400">
                            {v.value || <em className="text-gray-600">—</em>}
                          </span>
                        </span>
                        <button
                          onClick={() => handleRemoveVar(i)}
                          className="text-gray-500 hover:text-red-400 transition-colors ml-2"
                          aria-label={t('common.cancel')}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-700 sticky bottom-0 bg-gray-800">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
          >
            {t('common.cancel')}
          </button>
          <button
            onClick={handleRun}
            disabled={!canRun}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {t('playbooks.run')}
          </button>
        </div>
      </div>
    </div>
  )
}
