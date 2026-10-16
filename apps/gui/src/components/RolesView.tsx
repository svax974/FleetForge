/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Cog, Search, Play, AlertCircle, X, LayoutGrid, List } from 'lucide-react'
import { listAnsibleRoles } from '../lib/api'
import { AnsibleRole } from '../types'
import AnsibleDeployModal from './AnsibleDeployModal'
import { DeployLaunchConfig } from '../types'

type ViewMode = 'cards' | 'list'

interface RolesViewProps {
  configMissing: boolean
  onLaunchDeploy: (config: DeployLaunchConfig) => void
}

function RoleBadge({ label, color }: { label: string; color: string }) {
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${color}`}>
      {label}
    </span>
  )
}

function RoleCard({ role, onDeploy }: { role: AnsibleRole; onDeploy: (role: AnsibleRole) => void }) {
  const { t } = useTranslation()

  return (
    <div className="bg-gray-800 rounded-lg shadow-sm border border-gray-700 p-4 flex flex-col gap-3 hover:shadow-md hover:border-gray-600 transition-all">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Cog className="w-5 h-5 text-blue-400 shrink-0" />
          <div>
            <span className="font-semibold text-gray-100">{role.label}</span>
            <span className="block text-xs text-gray-500 font-mono">{role.name}</span>
          </div>
        </div>
        <button
          onClick={() => onDeploy(role)}
          className="flex items-center gap-1 px-3 py-1.5 bg-primary-600 hover:bg-primary-700 text-white rounded-md text-xs font-medium transition-colors shrink-0"
        >
          <Play className="w-3 h-3" />
          {t('common.deploy')}
        </button>
      </div>

      {role.description && (
        <p className="text-sm text-gray-500 leading-relaxed">{role.description}</p>
      )}

      <div className="flex flex-wrap gap-1.5">
        {role.has_tasks && (
          <RoleBadge label={t('roles.tasks')} color="bg-blue-900/50 text-blue-400" />
        )}
        {role.has_templates && (
          <RoleBadge label={t('roles.templates')} color="bg-purple-900/50 text-purple-400" />
        )}
        {role.has_handlers && (
          <RoleBadge label={t('roles.handlers')} color="bg-green-900/50 text-green-400" />
        )}
      </div>
    </div>
  )
}

function RoleRow({ role, onDeploy }: { role: AnsibleRole; onDeploy: (role: AnsibleRole) => void }) {
  const { t } = useTranslation()

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 bg-gray-800 hover:bg-gray-700/40 transition-colors">
      <Cog className="w-4 h-4 text-blue-400 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-medium text-gray-100 text-sm">{role.label}</span>
          <span className="text-xs text-gray-500 font-mono">{role.name}</span>
        </div>
        {role.description && (
          <p className="text-xs text-gray-500 truncate mt-0.5">{role.description}</p>
        )}
      </div>
      <div className="flex gap-1 shrink-0">
        {role.has_tasks && (
          <RoleBadge label={t('roles.tasks')} color="bg-blue-900/50 text-blue-400" />
        )}
        {role.has_templates && (
          <RoleBadge label={t('roles.templates')} color="bg-purple-900/50 text-purple-400" />
        )}
        {role.has_handlers && (
          <RoleBadge label={t('roles.handlers')} color="bg-green-900/50 text-green-400" />
        )}
      </div>
      <button
        onClick={() => onDeploy(role)}
        className="flex items-center gap-1 px-2.5 py-1 bg-primary-600 hover:bg-primary-700 text-white rounded-md text-xs font-medium transition-colors shrink-0"
      >
        <Play className="w-3 h-3" />
        {t('common.deploy')}
      </button>
    </div>
  )
}

export default function RolesView({ configMissing, onLaunchDeploy }: RolesViewProps) {
  const { t } = useTranslation()
  const [roles, setRoles] = useState<AnsibleRole[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [deployRole, setDeployRole] = useState<AnsibleRole | null>(null)
  const [viewMode, setViewMode] = useState<ViewMode>('cards')

  useEffect(() => {
    loadRoles()
  }, [])

  const loadRoles = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await listAnsibleRoles()
      setRoles(data)
    } catch (err) {
      setError(t('roles.no_roles'))
    } finally {
      setLoading(false)
    }
  }

  const filteredRoles = useMemo(() => {
    if (!search.trim()) return roles
    const q = search.toLowerCase()
    return roles.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.label.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q)
    )
  }, [roles, search])

  const groupedRoles = useMemo(() => {
    const map: Record<string, AnsibleRole[]> = {}
    for (const role of filteredRoles) {
      const cat = role.category || 'Autre'
      if (!map[cat]) map[cat] = []
      map[cat].push(role)
    }
    return map
  }, [filteredRoles])

  const handleDeploy = (role: AnsibleRole) => {
    setDeployRole(role)
  }

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center h-full">
        <p className="text-gray-500">{t('common.loading')}</p>
      </div>
    )
  }

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100">{t('roles.title')}</h1>
        <p className="text-gray-400 mt-2">{t('roles.subtitle')}</p>
      </div>

      {configMissing && (
        <div className="mb-4 flex items-center gap-2 bg-amber-900/30 border border-amber-700 text-amber-400 rounded-lg px-4 py-3">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span className="text-sm">{t('common.config_required')}</span>
        </div>
      )}

      {error && (
        <div className="mb-4 flex items-center gap-2 bg-red-900/30 border border-red-700 text-red-400 rounded-lg px-4 py-3">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span className="text-sm">{error}</span>
          <button onClick={() => setError(null)} className="ml-auto">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="mb-6 flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('roles.search_placeholder')}
            className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-600 text-gray-100 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 placeholder:text-gray-600"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <div className="flex items-center bg-gray-800 border border-gray-700 rounded-lg p-0.5 shrink-0">
          <button
            onClick={() => setViewMode('cards')}
            title={t('common.view_cards')}
            className={`p-1.5 rounded-md transition-colors ${viewMode === 'cards' ? 'bg-gray-700 text-gray-100' : 'text-gray-500 hover:text-gray-300'}`}
          >
            <LayoutGrid className="w-4 h-4" />
          </button>
          <button
            onClick={() => setViewMode('list')}
            title={t('common.view_list')}
            className={`p-1.5 rounded-md transition-colors ${viewMode === 'list' ? 'bg-gray-700 text-gray-100' : 'text-gray-500 hover:text-gray-300'}`}
          >
            <List className="w-4 h-4" />
          </button>
        </div>
      </div>

      {roles.length === 0 && !loading ? (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-8 text-center text-gray-500">
          <Cog className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-sm">{t('roles.no_roles')}</p>
        </div>
      ) : Object.keys(groupedRoles).length === 0 ? (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-8 text-center text-gray-500">
          <p className="text-sm">{t('roles.no_roles_search')}</p>
        </div>
      ) : (
        <div className="space-y-8">
          {Object.entries(groupedRoles)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([category, categoryRoles]) => (
              <div key={category}>
                <h2 className="text-lg font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider bg-gray-700 px-2 py-1 rounded">
                    {category}
                  </span>
                  <span className="text-sm text-gray-500 font-normal">
                    {categoryRoles.length}
                  </span>
                </h2>
                {viewMode === 'cards' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {categoryRoles.map((role) => (
                      <RoleCard key={role.path} role={role} onDeploy={handleDeploy} />
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-gray-700 overflow-hidden divide-y divide-gray-700/50">
                    {categoryRoles.map((role) => (
                      <RoleRow key={role.path} role={role} onDeploy={handleDeploy} />
                    ))}
                  </div>
                )}
              </div>
            ))}
        </div>
      )}

      {deployRole && (
        <AnsibleDeployModal
          role={deployRole}
          onClose={() => setDeployRole(null)}
          onLaunch={onLaunchDeploy}
        />
      )}
    </div>
  )
}
