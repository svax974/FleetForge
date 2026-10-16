/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { BookOpen, Search, Play, AlertCircle, X, Server, Cog, LayoutGrid, List } from 'lucide-react'
import { listAnsiblePlaybooks } from '../lib/api'
import { AnsiblePlaybook } from '../types'
import PlaybookRunModal from './PlaybookRunModal'
import { PlaybookLaunchConfig } from '../types'

type ViewMode = 'cards' | 'list'

interface PlaybooksViewProps {
  configMissing: boolean
  onLaunchPlaybook: (config: PlaybookLaunchConfig) => void
}

function PlaybookCard({
  playbook,
  onRun,
}: {
  playbook: AnsiblePlaybook
  onRun: (playbook: AnsiblePlaybook) => void
}) {
  const { t } = useTranslation()

  return (
    <div className="bg-gray-800 rounded-lg shadow-sm border border-gray-700 p-4 flex flex-col gap-3 hover:shadow-md hover:border-gray-600 transition-all">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-indigo-400 shrink-0" />
          <div>
            <span className="font-semibold text-gray-100">{playbook.label}</span>
            <span className="block text-xs text-gray-500 font-mono">{playbook.name}.yml</span>
          </div>
        </div>
        <button
          onClick={() => onRun(playbook)}
          className="flex items-center gap-1 px-3 py-1.5 bg-primary-600 hover:bg-primary-700 text-white rounded-md text-xs font-medium transition-colors shrink-0"
        >
          <Play className="w-3 h-3" />
          {t('playbooks.run')}
        </button>
      </div>

      {playbook.description && (
        <p className="text-sm text-gray-500 leading-relaxed">{playbook.description}</p>
      )}

      <div className="flex flex-col gap-1.5 text-xs text-gray-500">
        {playbook.hosts && (
          <div className="flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-gray-500 shrink-0" />
            <span className="font-medium text-gray-400">{t('playbooks.hosts')} :</span>
            <span className="font-mono bg-gray-900 border border-gray-700 px-1.5 py-0.5 rounded text-gray-300">
              {playbook.hosts}
            </span>
          </div>
        )}
        {playbook.roles.length > 0 && (
          <div className="flex items-start gap-1.5">
            <Cog className="w-3.5 h-3.5 text-gray-500 shrink-0 mt-0.5" />
            <span className="font-medium text-gray-400 shrink-0">{t('playbooks.roles_used')} :</span>
            <div className="flex flex-wrap gap-1">
              {playbook.roles.map((role) => (
                <span
                  key={role}
                  className="font-mono bg-indigo-900/40 text-indigo-400 border border-indigo-800/50 px-1.5 py-0.5 rounded"
                >
                  {role}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function PlaybookRow({
  playbook,
  onRun,
}: {
  playbook: AnsiblePlaybook
  onRun: (playbook: AnsiblePlaybook) => void
}) {
  const { t } = useTranslation()

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 bg-gray-800 hover:bg-gray-700/40 transition-colors">
      <BookOpen className="w-4 h-4 text-indigo-400 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-medium text-gray-100 text-sm">{playbook.label}</span>
          <span className="text-xs text-gray-500 font-mono">{playbook.name}.yml</span>
        </div>
        {playbook.description && (
          <p className="text-xs text-gray-500 truncate mt-0.5">{playbook.description}</p>
        )}
      </div>
      {playbook.hosts && (
        <div className="flex items-center gap-1 shrink-0">
          <Server className="w-3 h-3 text-gray-500" />
          <span className="font-mono text-xs bg-gray-900 border border-gray-700 px-1.5 py-0.5 rounded text-gray-300">
            {playbook.hosts}
          </span>
        </div>
      )}
      {playbook.roles.length > 0 && (
        <div className="flex flex-wrap gap-1 shrink-0">
          {playbook.roles.map((role) => (
            <span
              key={role}
              className="font-mono text-xs bg-indigo-900/40 text-indigo-400 border border-indigo-800/50 px-1.5 py-0.5 rounded"
            >
              {role}
            </span>
          ))}
        </div>
      )}
      <button
        onClick={() => onRun(playbook)}
        className="flex items-center gap-1 px-2.5 py-1 bg-primary-600 hover:bg-primary-700 text-white rounded-md text-xs font-medium transition-colors shrink-0"
      >
        <Play className="w-3 h-3" />
        {t('playbooks.run')}
      </button>
    </div>
  )
}

export default function PlaybooksView({ configMissing, onLaunchPlaybook }: PlaybooksViewProps) {
  const { t } = useTranslation()
  const [playbooks, setPlaybooks] = useState<AnsiblePlaybook[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [runPlaybook, setRunPlaybook] = useState<AnsiblePlaybook | null>(null)
  const [viewMode, setViewMode] = useState<ViewMode>('cards')

  useEffect(() => {
    loadPlaybooks()
  }, [])

  const loadPlaybooks = async (): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      const data = await listAnsiblePlaybooks()
      setPlaybooks(data)
    } catch (err) {
      setError(t('playbooks.no_playbooks'))
    } finally {
      setLoading(false)
    }
  }

  const filteredPlaybooks = useMemo(() => {
    if (!search.trim()) return playbooks
    const q = search.toLowerCase()
    return playbooks.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.label.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.hosts.toLowerCase().includes(q) ||
        p.roles.some((r) => r.toLowerCase().includes(q))
    )
  }, [playbooks, search])

  const groupedPlaybooks = useMemo(() => {
    const map: Record<string, AnsiblePlaybook[]> = {}
    for (const pb of filteredPlaybooks) {
      const cat = pb.category || 'Autre'
      if (!map[cat]) map[cat] = []
      map[cat].push(pb)
    }
    return map
  }, [filteredPlaybooks])

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
        <h1 className="text-3xl font-bold text-gray-100">{t('playbooks.title')}</h1>
        <p className="text-gray-400 mt-2">{t('playbooks.subtitle')}</p>
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
            placeholder={t('playbooks.search_placeholder')}
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

      {playbooks.length === 0 && !loading ? (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-8 text-center text-gray-500">
          <BookOpen className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-sm">{t('playbooks.no_playbooks')}</p>
        </div>
      ) : Object.keys(groupedPlaybooks).length === 0 ? (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-8 text-center text-gray-500">
          <p className="text-sm">{t('playbooks.no_playbooks_search')}</p>
        </div>
      ) : (
        <div className="space-y-8">
          {Object.entries(groupedPlaybooks)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([category, categoryPlaybooks]) => (
              <div key={category}>
                <h2 className="text-lg font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider bg-gray-700 px-2 py-1 rounded">
                    {category}
                  </span>
                  <span className="text-sm text-gray-500 font-normal">
                    {categoryPlaybooks.length}
                  </span>
                </h2>
                {viewMode === 'cards' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {categoryPlaybooks.map((pb) => (
                      <PlaybookCard key={pb.path} playbook={pb} onRun={setRunPlaybook} />
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-gray-700 overflow-hidden divide-y divide-gray-700/50">
                    {categoryPlaybooks.map((pb) => (
                      <PlaybookRow key={pb.path} playbook={pb} onRun={setRunPlaybook} />
                    ))}
                  </div>
                )}
              </div>
            ))}
        </div>
      )}

      {runPlaybook && (
        <PlaybookRunModal
          playbook={runPlaybook}
          onClose={() => setRunPlaybook(null)}
          onLaunch={onLaunchPlaybook}
        />
      )}
    </div>
  )
}
