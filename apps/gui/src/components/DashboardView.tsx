import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity, Cpu, BookOpen, Cog,
  CheckCircle, XCircle,
  Clock, ArrowRight, Settings, RefreshCw
} from 'lucide-react'
import {
  getModels,
  listAnsiblePlaybooks, listAnsibleRoles,
  getAnsibleRuns,
  checkAnsibleAvailable, getInventoriesPath, getPlaybooksPath, getSelectedInventory,
  queryPrometheus, getPrometheusUrl,
} from '../lib/api'
import { AnsibleRun, PrometheusMetric } from '../types'
import { View } from '../App'

function formatDate(dateStr: string, language: string): string {
  try {
    return new Intl.DateTimeFormat(language === 'fr' ? 'fr-FR' : 'en-US', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(new Date(dateStr))
  } catch { return dateStr }
}

function RunStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation()
  if (status === 'success') return <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-900/50 text-green-400"><CheckCircle className="w-3 h-3" />{t('common.yes')}</span>
  if (status === 'failed') return <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-900/50 text-red-400"><XCircle className="w-3 h-3" />{t('common.no')}</span>
  return <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-yellow-900/50 text-yellow-400"><Clock className="w-3 h-3" />{t('common.loading')}</span>
}

interface ServerProbeStatus {
  instance: string
  job: string
  up: boolean
}

function parseServerStatuses(metrics: PrometheusMetric[]): ServerProbeStatus[] {
  return metrics.map((m) => ({
    instance: m.metric['instance'] ?? m.metric['__name__'] ?? '?',
    job: m.metric['job'] ?? 'node_exporter',
    up: m.value === '1',
  }))
}

interface DashboardViewProps {
  onNavigate: (view: View) => void
}

export default function DashboardView({ onNavigate }: DashboardViewProps) {
  const { t, i18n } = useTranslation()
  const [stats, setStats] = useState({ models: 0, playbooks: 0, roles: 0 })
  const [recentRuns, setRecentRuns] = useState<AnsibleRun[]>([])
  const [ansibleAvailable, setAnsibleAvailable] = useState<boolean | null>(null)
  const [inventoriesPath, setInventoriesPath] = useState('')
  const [playbooksPath, setPlaybooksPath] = useState('')
  const [selectedInv, setSelectedInv] = useState('')
  const [serverStatuses, setServerStatuses] = useState<ServerProbeStatus[]>([])
  const [checkingServers, setCheckingServers] = useState(false)
  const [prometheusConfigured, setPrometheusConfigured] = useState(true)

  useEffect(() => {
    loadStats()
    loadRecentRuns()
    loadSystemInfo()
    loadServerStatuses()
  }, [])

  const loadStats = async () => {
    try {
      const [models, playbooks, roles] = await Promise.all([
        getModels(),
        listAnsiblePlaybooks().catch(() => []),
        listAnsibleRoles().catch(() => []),
      ])
      setStats({ models: models.length, playbooks: playbooks.length, roles: roles.length })
    } catch { /* empty state */ }
  }

  const loadRecentRuns = async () => {
    try {
      const runs = await getAnsibleRuns()
      setRecentRuns(runs.slice(-5).reverse())
    } catch { /* empty state */ }
  }

  const loadSystemInfo = async () => {
    try {
      const [available, invPath, pbPath, inv] = await Promise.all([
        checkAnsibleAvailable().catch(() => false),
        getInventoriesPath().catch(() => ''),
        getPlaybooksPath().catch(() => ''),
        getSelectedInventory().catch(() => ''),
      ])
      setAnsibleAvailable(available)
      setInventoriesPath(invPath)
      setPlaybooksPath(pbPath)
      setSelectedInv(inv)
    } catch { /* empty state */ }
  }

  const loadServerStatuses = async () => {
    setCheckingServers(true)
    try {
      const url = await getPrometheusUrl().catch(() => '')
      if (!url) {
        setPrometheusConfigured(false)
        setServerStatuses([])
        return
      }
      setPrometheusConfigured(true)
      // Query all node_exporter probes (both up and down)
      const [upMetrics, allMetrics] = await Promise.all([
        queryPrometheus('up{job="exporter"}').catch(() => [] as PrometheusMetric[]),
        queryPrometheus('up{job="exporter"} == 0').catch(() => [] as PrometheusMetric[]),
      ])
      // Merge: use upMetrics as the source, mark down ones from allMetrics
      const downInstances = new Set(allMetrics.map((m) => m.metric['instance']))
      const statuses = parseServerStatuses(upMetrics).map((s) => ({
        ...s,
        up: !downInstances.has(s.instance),
      }))
      // Sort: down first, then alphabetical
      statuses.sort((a, b) => {
        if (a.up !== b.up) return a.up ? 1 : -1
        return a.instance.localeCompare(b.instance)
      })
      setServerStatuses(statuses)
    } catch {
      setServerStatuses([])
    } finally {
      setCheckingServers(false)
    }
  }

  const cards = [
    { title: t('dashboard.ansible_playbooks'), value: stats.playbooks, icon: BookOpen, color: 'bg-teal-500' },
    { title: t('dashboard.ansible_roles'), value: stats.roles, icon: Cog, color: 'bg-indigo-500' },
    { title: t('dashboard.ai_models'), value: stats.models, icon: Cpu, color: 'bg-purple-500' },
  ]

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100">{t('dashboard.title')}</h1>
        <p className="text-gray-400 mt-2">{t('dashboard.subtitle')}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {cards.map((card) => {
          const Icon = card.icon
          return (
            <div key={card.title} className="bg-gray-800 rounded-lg shadow-md p-5 border border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-gray-500 leading-tight">{card.title}</p>
                  <p className="text-3xl font-bold text-gray-100 mt-1">{card.value}</p>
                </div>
                <div className={`${card.color} p-2.5 rounded-lg shrink-0`}>
                  <Icon className="w-5 h-5 text-white" />
                </div>
              </div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">

          {/* Server Status via Prometheus */}
          <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-gray-200">{t('dashboard.server_status')}</h3>
              <div className="flex items-center gap-2">
                {!prometheusConfigured && (
                  <button
                    onClick={() => onNavigate('configuration')}
                    className="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                  >
                    {t('monitoring.go_to_config')}
                  </button>
                )}
                <button
                  onClick={loadServerStatuses}
                  disabled={checkingServers}
                  className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 disabled:opacity-50 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${checkingServers ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            {!prometheusConfigured ? (
              <p className="text-sm text-gray-500 py-4 text-center">{t('monitoring.not_configured')}</p>
            ) : checkingServers ? (
              <p className="text-sm text-gray-500 py-4 text-center">{t('common.loading')}</p>
            ) : serverStatuses.length === 0 ? (
              <p className="text-sm text-gray-500 py-4 text-center">{t('dashboard.no_servers')}</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {serverStatuses.map((s) => (
                  <div key={s.instance} className="flex items-center gap-2 px-3 py-2 bg-gray-900 rounded-lg">
                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${s.up ? 'bg-green-500' : 'bg-red-500 animate-pulse'}`} />
                    <span className="text-sm font-medium text-gray-200 truncate">{s.instance}</span>
                    {!s.up && (
                      <span className="ml-auto text-xs font-semibold text-red-400 shrink-0">{t('monitoring.down')}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent Ansible runs */}
          <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-gray-200">{t('dashboard.recent_runs')}</h3>
              <button
                onClick={() => onNavigate('ansible-runs')}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                {t('common.actions')}
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
            {recentRuns.length === 0 ? (
              <p className="text-sm text-gray-500 py-4 text-center">{t('dashboard.no_runs')}</p>
            ) : (
              <div className="divide-y divide-gray-700">
                {recentRuns.map((run, idx) => (
                  <div key={run.id ?? idx} className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                    <span className="text-xs text-gray-500 font-mono shrink-0 w-28">
                      {formatDate(run.started_at, i18n.language)}
                    </span>
                    <div className="flex flex-wrap gap-1 flex-1 min-w-0">
                      {run.roles.map((role) => (
                        <span key={role} className="text-xs px-2 py-0.5 rounded-full bg-blue-900/50 text-blue-400">
                          {role}
                        </span>
                      ))}
                    </div>
                    <RunStatusBadge status={run.status} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-gray-200">{t('dashboard.system_info')}</h3>
              <Settings className="w-4 h-4 text-gray-500" />
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">{t('dashboard.ansible_available')}</span>
                {ansibleAvailable === null ? (
                  <span className="text-xs text-gray-500">{t('common.loading')}</span>
                ) : ansibleAvailable ? (
                  <span className="inline-flex items-center gap-1 text-xs text-green-400">
                    <CheckCircle className="w-3.5 h-3.5" />{t('common.yes')}
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-red-400">
                    <XCircle className="w-3.5 h-3.5" />{t('common.no')}
                  </span>
                )}
              </div>
              {inventoriesPath && (
                <div>
                  <p className="text-xs font-medium text-gray-500 mb-0.5">{t('dashboard.inventories_path')}</p>
                  <p className="text-xs text-gray-300 font-mono truncate">{inventoriesPath}</p>
                </div>
              )}
              {playbooksPath && (
                <div>
                  <p className="text-xs font-medium text-gray-500 mb-0.5">{t('dashboard.playbooks_path')}</p>
                  <p className="text-xs text-gray-300 font-mono truncate">{playbooksPath}</p>
                </div>
              )}
              {selectedInv && (
                <div>
                  <p className="text-xs font-medium text-gray-500 mb-0.5">{t('dashboard.selected_inventory')}</p>
                  <p className="text-xs text-gray-300 font-mono truncate">{selectedInv}</p>
                </div>
              )}
              {!inventoriesPath && !playbooksPath && !selectedInv && ansibleAvailable !== null && (
                <p className="text-xs text-gray-500">{t('dashboard.not_configured')}</p>
              )}
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-gray-200">{t('dashboard.quick_actions')}</h3>
              <Activity className="w-4 h-4 text-gray-500" />
            </div>
            <div className="space-y-2">
              <button
                onClick={() => onNavigate('roles')}
                className="w-full flex items-center gap-2 px-3 py-2.5 bg-gray-900 rounded-lg text-sm text-gray-300 hover:bg-gray-700 transition-colors text-left"
              >
                <Cog className="w-4 h-4 text-indigo-400 shrink-0" />
                {t('dashboard.deploy_roles')}
              </button>
              <button
                onClick={() => onNavigate('playbooks')}
                className="w-full flex items-center gap-2 px-3 py-2.5 bg-gray-900 rounded-lg text-sm text-gray-300 hover:bg-gray-700 transition-colors text-left"
              >
                <BookOpen className="w-4 h-4 text-teal-400 shrink-0" />
                {t('nav.playbooks')}
              </button>
              <button
                onClick={() => onNavigate('monitoring')}
                className="w-full flex items-center gap-2 px-3 py-2.5 bg-gray-900 rounded-lg text-sm text-gray-300 hover:bg-gray-700 transition-colors text-left"
              >
                <Activity className="w-4 h-4 text-green-400 shrink-0" />
                {t('nav.monitoring')}
              </button>
              <button
                onClick={() => onNavigate('models')}
                className="w-full flex items-center gap-2 px-3 py-2.5 bg-gray-900 rounded-lg text-sm text-gray-300 hover:bg-gray-700 transition-colors text-left"
              >
                <Cpu className="w-4 h-4 text-purple-400 shrink-0" />
                {t('dashboard.manage_models')}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
