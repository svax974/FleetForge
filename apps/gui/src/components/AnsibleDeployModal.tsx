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
  Brain,
} from 'lucide-react'
import {
  getSelectedInventory,
  getInventoryGroups,
  listAnsibleRoles,
  checkAnsibleAvailable,
  getServerCurrentServices,
} from '../lib/api'
import { AnsibleRole, AnsibleGroup, AnsibleHost, DeployLaunchConfig } from '../types'

const OLLAMA_ROLE = 'ollama-model-install'

interface AnsibleDeployModalProps {
  role: AnsibleRole
  initialHosts?: string[]
  onClose: () => void
  onLaunch: (config: DeployLaunchConfig) => void
}

interface ExtraVar {
  key: string
  value: string
}

function RolePill({ role, onRemove }: { role: AnsibleRole; onRemove: () => void }) {
  const { t } = useTranslation()
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-900/50 text-blue-300 text-xs font-medium rounded-full">
      {role.label || role.name}
      <button onClick={onRemove} className="ml-0.5 hover:text-blue-200 focus:outline-none" aria-label={`${t('common.cancel')} ${role.label || role.name}`}>
        <X className="w-3 h-3" />
      </button>
    </span>
  )
}

function GroupBlock({
  group,
  selectedHosts,
  onToggleHost,
  eligibleHosts,
}: {
  group: AnsibleGroup
  selectedHosts: Set<string>
  onToggleHost: (host: AnsibleHost) => void
  eligibleHosts: Set<string> | null
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(true)

  const visibleHosts = eligibleHosts ? group.hosts.filter((h) => eligibleHosts.has(h.name)) : group.hosts
  const allSelected = visibleHosts.length > 0 && visibleHosts.every((h) => selectedHosts.has(h.name))
  const someSelected = visibleHosts.some((h) => selectedHosts.has(h.name)) && !allSelected

  const handleSelectAll = () => {
    if (allSelected) visibleHosts.forEach((h) => { if (selectedHosts.has(h.name)) onToggleHost(h) })
    else visibleHosts.forEach((h) => { if (!selectedHosts.has(h.name)) onToggleHost(h) })
  }

  if (visibleHosts.length === 0 && group.children.length === 0) return null

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-gray-700 border-b border-gray-600">
        <button onClick={() => setExpanded((v) => !v)} className="flex items-center gap-1.5 text-sm font-medium text-gray-300 hover:text-gray-100">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          {group.name}
          <span className="text-xs text-gray-500 font-normal">({visibleHosts.length})</span>
        </button>
        {visibleHosts.length > 0 && (
          <button onClick={handleSelectAll} className="text-xs text-primary-400 hover:text-primary-300 font-medium">
            {allSelected || someSelected ? t('ansible_deploy.deselect_all') : t('ansible_deploy.select_all')}
          </button>
        )}
      </div>
      {expanded && (
        <div className="divide-y divide-gray-700">
          {visibleHosts.map((host) => (
            <label key={host.name} className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-700/50 transition-colors">
              <input type="checkbox" checked={selectedHosts.has(host.name)} onChange={() => onToggleHost(host)} className="w-4 h-4 text-primary-600 border-gray-600 rounded focus:ring-primary-500 bg-gray-900" />
              <span className="text-sm font-medium text-gray-100">{host.name}</span>
              {host.ansible_host && <span className="text-xs text-gray-500 font-mono ml-auto">{host.ansible_host}</span>}
            </label>
          ))}
          {group.children.map((child) => (
            <div key={child.name} className="pl-4">
              <GroupBlock group={child} selectedHosts={selectedHosts} onToggleHost={onToggleHost} eligibleHosts={eligibleHosts} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AnsibleDeployModal({ role, initialHosts, onClose, onLaunch }: AnsibleDeployModalProps) {
  const { t } = useTranslation()

  const [loadingInit, setLoadingInit] = useState(true)
  const [initError, setInitError] = useState<string | null>(null)
  const [ansibleAvailable, setAnsibleAvailable] = useState(true)

  const [inventoryPath, setInventoryPath] = useState<string>('')
  const [groups, setGroups] = useState<AnsibleGroup[]>([])
  const [allRoles, setAllRoles] = useState<AnsibleRole[]>([])

  const [selectedRoles, setSelectedRoles] = useState<AnsibleRole[]>([role])
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set(initialHosts ?? []))
  const [roleToAdd, setRoleToAdd] = useState<string>('')

  const [ollamaModelName, setOllamaModelName] = useState('')
  const [ollamaHosts, setOllamaHosts] = useState<Set<string> | null>(null)

  const [extraVars, setExtraVars] = useState<ExtraVar[]>([])
  const [newVarKey, setNewVarKey] = useState('')
  const [newVarValue, setNewVarValue] = useState('')

  const hasOllamaRole = selectedRoles.some((r) => r.name === OLLAMA_ROLE)

  useEffect(() => { initModal() }, [])

  useEffect(() => {
    if (!hasOllamaRole) setOllamaModelName('')
  }, [hasOllamaRole])

  const initModal = async () => {
    setLoadingInit(true)
    setInitError(null)
    try {
      const [available, invPath, roles, services] = await Promise.all([
        checkAnsibleAvailable(),
        getSelectedInventory(),
        listAnsibleRoles(),
        getServerCurrentServices(),
      ])
      setAnsibleAvailable(available)
      setInventoryPath(invPath)
      setAllRoles(roles)
      const withOllama = new Set(
        services.filter((s) => s.service_name === 'ollama').map((s) => s.server_name)
      )
      setOllamaHosts(withOllama)
      if (invPath) {
        const grps = await getInventoryGroups(invPath)
        setGroups(grps)
      }
    } catch {
      setInitError(t('ansible_deploy.deploy_failed'))
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

  const handleAddRole = () => {
    if (!roleToAdd) return
    const found = allRoles.find((r) => r.name === roleToAdd)
    if (!found || selectedRoles.some((r) => r.name === found.name)) return
    setSelectedRoles((prev) => [...prev, found])
    setRoleToAdd('')
  }

  const handleRemoveRole = (roleName: string) => {
    setSelectedRoles((prev) => prev.filter((r) => r.name !== roleName))
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

  const handleDeploy = () => {
    if (selectedRoles.length === 0 || selectedHosts.size === 0) return
    if (hasOllamaRole && !ollamaModelName.trim()) return

    const varsMap: Record<string, string> = {}
    extraVars.forEach((v) => { if (v.key) varsMap[v.key] = v.value })
    if (hasOllamaRole && ollamaModelName.trim()) {
      varsMap['ollama_model_name'] = ollamaModelName.trim()
    }

    const config: DeployLaunchConfig = {
      id: crypto.randomUUID(),
      label: hasOllamaRole && ollamaModelName.trim()
        ? `${t('ansible_deploy.ollama_model_label')} ${ollamaModelName.trim()}`
        : selectedRoles.map((r) => r.label || r.name).join(', '),
      inventoryPath,
      roles: selectedRoles.map((r) => r.name),
      hosts: Array.from(selectedHosts),
      extraVars: Object.keys(varsMap).length > 0 ? varsMap : undefined,
    }

    onLaunch(config)
    onClose()
  }

  const availableRolesToAdd = allRoles.filter((r) => !selectedRoles.some((sr) => sr.name === r.name))

  const canDeploy =
    ansibleAvailable &&
    selectedRoles.length > 0 &&
    selectedHosts.size > 0 &&
    (!hasOllamaRole || !!ollamaModelName.trim())

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl shadow-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto border border-gray-700">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <h2 className="text-xl font-bold text-gray-100">{t('ansible_deploy.title')}</h2>
          <button onClick={onClose} className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
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
              {t('ansible_deploy.deploy_failed')}
            </div>
          )}

          {!loadingInit && (
            <>
              {/* Inventory */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-1">{t('ansible_deploy.select_inventory_first')}</p>
                <p className="text-sm text-gray-400 font-mono bg-gray-900 border border-gray-700 rounded px-3 py-2">
                  {inventoryPath || <span className="text-gray-600 italic">{t('ansible_deploy.no_inventory')}</span>}
                </p>
              </div>

              {/* Selected roles */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-2">{t('ansible_deploy.selected_roles')}</p>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedRoles.map((r) => (
                    <RolePill key={r.name} role={r} onRemove={() => handleRemoveRole(r.name)} />
                  ))}
                  {availableRolesToAdd.length > 0 && (
                    <div className="flex items-center gap-1.5">
                      <select value={roleToAdd} onChange={(e) => setRoleToAdd(e.target.value)} className="text-xs border border-gray-600 rounded-md px-2 py-1 focus:outline-none focus:ring-2 focus:ring-primary-500 bg-gray-900 text-gray-300">
                        <option value="">{t('ansible_deploy.search_roles')}</option>
                        {availableRolesToAdd.map((r) => (
                          <option key={r.name} value={r.name}>{r.label || r.name}</option>
                        ))}
                      </select>
                      <button onClick={handleAddRole} disabled={!roleToAdd} className="p-1 bg-primary-600 hover:bg-primary-700 text-white rounded-md disabled:opacity-40 transition-colors" aria-label={t('ansible_deploy.select_roles')}>
                        <Plus className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
                {selectedRoles.length === 0 && <p className="mt-2 text-xs text-red-400">{t('ansible_deploy.no_roles_selected')}</p>}
              </div>

              {/* Ollama model name */}
              {hasOllamaRole && (
                <div className="border border-purple-700/50 bg-purple-900/10 rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-purple-400 shrink-0" />
                    <label className="text-sm font-medium text-purple-300">{t('ansible_deploy.ollama_model_label')}</label>
                  </div>
                  <input
                    type="text"
                    placeholder="qwen2.5-coder:1.5b"
                    value={ollamaModelName}
                    onChange={(e) => setOllamaModelName(e.target.value)}
                    className="w-full px-3 py-2 text-sm font-mono bg-gray-900 border border-gray-700 rounded-lg text-gray-100 placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                  <p className="text-xs text-gray-500">{t('ansible_deploy.ollama_model_hint')}</p>
                  {!ollamaModelName.trim() && (
                    <p className="text-xs text-red-400">{t('ansible_deploy.ollama_model_required')}</p>
                  )}
                </div>
              )}

              {/* Host selection */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-2">
                  {t('ansible_deploy.select_hosts')}{' '}
                  {selectedHosts.size > 0 && <span className="text-primary-400">({selectedHosts.size})</span>}
                </p>
                {hasOllamaRole && ollamaHosts !== null && ollamaHosts.size === 0 ? (
                  <div className="flex items-center gap-2 bg-yellow-900/30 border border-yellow-700 text-yellow-400 rounded-lg px-4 py-3 text-sm">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    {t('ansible_deploy.ollama_no_hosts')}
                  </div>
                ) : groups.length === 0 && !inventoryPath ? (
                  <p className="text-sm text-gray-500 italic">{t('ansible_deploy.no_inventory')}</p>
                ) : groups.length === 0 ? (
                  <p className="text-sm text-gray-500 italic">{t('ansible_deploy.select_inventory_first')}</p>
                ) : (
                  <div className="space-y-2">
                    {groups.map((group) => (
                      <GroupBlock
                        key={group.name}
                        group={group}
                        selectedHosts={selectedHosts}
                        onToggleHost={handleToggleHost}
                        eligibleHosts={hasOllamaRole ? ollamaHosts : null}
                      />
                    ))}
                  </div>
                )}
                {selectedHosts.size === 0 && groups.length > 0 && <p className="mt-2 text-xs text-red-400">{t('ansible_deploy.no_hosts_selected')}</p>}
              </div>

              {/* Extra variables */}
              <div>
                <p className="text-sm font-medium text-gray-300 mb-2">
                  {t('ansible_deploy.extra_vars')}{' '}
                  <span className="text-gray-500 font-normal">(optionnel)</span>
                </p>
                <div className="flex items-center gap-2 mb-2">
                  <input type="text" placeholder={t('ansible_deploy.var_name')} value={newVarKey} onChange={(e) => setNewVarKey(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAddVar()} className="flex-1 text-sm border border-gray-600 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500 bg-gray-900 text-gray-100 placeholder:text-gray-600" />
                  <input type="text" placeholder={t('ansible_deploy.var_value')} value={newVarValue} onChange={(e) => setNewVarValue(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAddVar()} className="flex-1 text-sm border border-gray-600 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500 bg-gray-900 text-gray-100 placeholder:text-gray-600" />
                  <button onClick={handleAddVar} disabled={!newVarKey.trim()} className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs font-medium rounded-md transition-colors disabled:opacity-40">
                    <Plus className="w-3.5 h-3.5" />
                    {t('ansible_deploy.add_variable')}
                  </button>
                </div>
                {extraVars.length > 0 && (
                  <ul className="space-y-1">
                    {extraVars.map((v, i) => (
                      <li key={i} className="flex items-center justify-between text-sm bg-gray-900 border border-gray-700 rounded px-3 py-1.5">
                        <span>
                          <span className="font-mono text-gray-300">{v.key}</span>
                          <span className="text-gray-500 mx-1">=</span>
                          <span className="font-mono text-gray-400">{v.value || <em className="text-gray-600">—</em>}</span>
                        </span>
                        <button onClick={() => handleRemoveVar(i)} className="text-gray-500 hover:text-red-400 transition-colors ml-2" aria-label={t('common.cancel')}>
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
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
            {t('common.cancel')}
          </button>
          <button onClick={handleDeploy} disabled={!canDeploy} className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
            {t('common.deploy')}
          </button>
        </div>
      </div>
    </div>
  )
}
