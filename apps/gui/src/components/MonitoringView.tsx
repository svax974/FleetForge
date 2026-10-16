/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity, RefreshCw, AlertTriangle, CheckCircle,
  XCircle, Server, Cpu, AlertCircle, Settings, ChevronRight,
} from 'lucide-react'
import { queryPrometheus, getPrometheusUrl } from '../lib/api'
import { PrometheusMetric } from '../types'
import { View } from '../App'

const SYSTEM_JOB = 'exporter'

interface MonitoringViewProps {
  onNavigate: (view: View) => void
}

function downVariant(count: number): { card: string; value: string } {
  if (count === 0) return { card: 'border-green-700 bg-green-900/20', value: 'text-green-400' }
  if (count <= 5) return { card: 'border-orange-700 bg-orange-900/20', value: 'text-orange-400' }
  return { card: 'border-red-700 bg-red-900/20', value: 'text-red-400' }
}

function MetricLabels({ metric }: { metric: Record<string, string> }) {
  const extra = Object.entries(metric).filter(
    ([k]) => k !== '__name__' && k !== 'instance' && k !== 'job'
  )
  if (extra.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {extra.map(([k, v]) => (
        <span key={k} className="text-xs font-mono px-1.5 py-0.5 rounded bg-gray-900 border border-gray-700 text-gray-400">
          {k}=<span className="text-gray-300">{v}</span>
        </span>
      ))}
    </div>
  )
}

interface CollapsibleProbeListProps {
  label: string
  probes: PrometheusMetric[]
  isUp: boolean
}

function CollapsibleProbeList({ label, probes, isUp }: CollapsibleProbeListProps) {
  const [open, setOpen] = useState(false)

  const countColor = isUp ? 'text-green-400' : probes.length === 0 ? 'text-green-400' : 'text-red-400'
  const rowBg = isUp
    ? 'bg-green-900/10 border border-green-900/30'
    : probes.length > 0
      ? 'bg-red-900/10 border border-red-900/30'
      : 'bg-green-900/10 border border-green-900/30'

  return (
    <div className="rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className={`w-full flex items-center gap-2 px-3 py-2.5 text-left transition-colors hover:brightness-110 ${rowBg}`}
      >
        <ChevronRight className={`w-4 h-4 text-gray-400 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`} />
        <span className="text-sm font-medium text-gray-300 flex-1">{label}</span>
        <span className={`text-sm font-bold ${countColor}`}>{probes.length}</span>
      </button>

      {open && (
        <div className="border-t border-gray-700 divide-y divide-gray-800">
          {probes.length === 0 ? (
            <div className="px-4 py-2 text-xs text-gray-500 italic">—</div>
          ) : (
            probes.map((p, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                {isUp
                  ? <CheckCircle className="w-3.5 h-3.5 text-green-500 shrink-0 mt-0.5" />
                  : <XCircle className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
                }
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-sm font-mono font-medium ${isUp ? 'text-green-300' : 'text-red-300'}`}>
                      {p.metric.instance ?? '—'}
                    </span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-500">
                      {p.metric.job ?? '—'}
                    </span>
                  </div>
                  <MetricLabels metric={p.metric} />
                </div>
                {!isUp && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-900/40 border border-red-800 text-red-400 shrink-0">
                    DOWN
                  </span>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

interface ProbeSectionProps {
  upProbes: PrometheusMetric[]
  downProbes: PrometheusMetric[]
  loading: boolean
  error: string | null
  upLabel: string
  downLabel: string
}

function ProbeSection({ upProbes, downProbes, loading, error, upLabel, downLabel }: ProbeSectionProps) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 text-gray-500 text-sm py-6 justify-center">
        <RefreshCw className="w-4 h-4 animate-spin" />
        <span>Chargement...</span>
      </div>
    )
  }
  if (error) {
    return (
      <div className="flex items-start gap-2 text-red-400 text-sm py-4 px-3 bg-red-900/20 border border-red-800 rounded-lg">
        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
        <span className="font-mono break-all">{error}</span>
      </div>
    )
  }
  return (
    <div className="space-y-2">
      <CollapsibleProbeList label={upLabel} probes={upProbes} isUp={true} />
      <CollapsibleProbeList label={downLabel} probes={downProbes} isUp={false} />
    </div>
  )
}

export default function MonitoringView({ onNavigate }: MonitoringViewProps) {
  const { t } = useTranslation()

  const [prometheusUrl, setPrometheusUrl] = useState<string>('')
  const [urlLoaded, setUrlLoaded] = useState(false)

  const [systemUpProbes, setSystemUpProbes] = useState<PrometheusMetric[]>([])
  const [systemDownProbes, setSystemDownProbes] = useState<PrometheusMetric[]>([])
  const [serviceUpProbes, setServiceUpProbes] = useState<PrometheusMetric[]>([])
  const [serviceDownProbes, setServiceDownProbes] = useState<PrometheusMetric[]>([])
  const [systemLoading, setSystemLoading] = useState(false)
  const [serviceLoading, setServiceLoading] = useState(false)
  const [systemError, setSystemError] = useState<string | null>(null)
  const [serviceError, setServiceError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  useEffect(() => {
    getPrometheusUrl().then((url) => {
      setPrometheusUrl(url)
      setUrlLoaded(true)
    }).catch(() => setUrlLoaded(true))
  }, [])

  const refresh = useCallback(async () => {
    if (!prometheusUrl) return

    setSystemLoading(true)
    setServiceLoading(true)
    setSystemError(null)
    setServiceError(null)

    const [sysUpResult, sysDownResult, svcUpResult, svcDownResult] = await Promise.allSettled([
      queryPrometheus(`up{job="${SYSTEM_JOB}"} == 1`),
      queryPrometheus(`up{job="${SYSTEM_JOB}"} == 0`),
      queryPrometheus(`up{job!="${SYSTEM_JOB}",job!="prometheus"} == 1`),
      queryPrometheus(`up{job!="${SYSTEM_JOB}",job!="prometheus"} == 0`),
    ])

    if (sysUpResult.status === 'fulfilled') {
      setSystemUpProbes(sysUpResult.value)
    } else {
      setSystemError(String(sysUpResult.reason))
    }
    if (sysDownResult.status === 'fulfilled') {
      setSystemDownProbes(sysDownResult.value)
    } else if (!systemError) {
      setSystemError(String(sysDownResult.reason))
    }
    setSystemLoading(false)

    if (svcUpResult.status === 'fulfilled') {
      setServiceUpProbes(svcUpResult.value)
    } else {
      setServiceError(String(svcUpResult.reason))
    }
    if (svcDownResult.status === 'fulfilled') {
      setServiceDownProbes(svcDownResult.value)
    } else if (!serviceError) {
      setServiceError(String(svcDownResult.reason))
    }
    setServiceLoading(false)

    setLastRefresh(new Date())
  }, [prometheusUrl])

  useEffect(() => {
    if (urlLoaded && prometheusUrl) {
      refresh()
    }
  }, [urlLoaded, prometheusUrl, refresh])

  const systemDown = systemDownProbes.length
  const serviceDown = serviceDownProbes.length
  const systemVariant = downVariant(systemDown)
  const serviceVariant = downVariant(serviceDown)
  const isLoading = systemLoading || serviceLoading

  return (
    <div className="p-8">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 flex items-center gap-3">
            <Activity className="w-8 h-8 text-primary-400" />
            {t('monitoring.title')}
          </h1>
          <p className="text-gray-400 mt-2">{t('monitoring.subtitle')}</p>
          {lastRefresh && (
            <p className="text-xs text-gray-600 mt-1">
              {t('monitoring.last_refresh')} {lastRefresh.toLocaleTimeString()}
            </p>
          )}
        </div>
        <button
          onClick={refresh}
          disabled={isLoading || !prometheusUrl}
          className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 text-gray-300 rounded-lg text-sm hover:bg-gray-700 transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          {t('monitoring.refresh')}
        </button>
      </div>

      {urlLoaded && !prometheusUrl && (
        <div className="mb-6 flex items-start gap-3 bg-yellow-900/20 border border-yellow-700 text-yellow-300 rounded-lg px-5 py-4">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sm">{t('monitoring.not_configured')}</p>
            <button
              onClick={() => onNavigate('configuration')}
              className="flex items-center gap-1.5 mt-2 text-xs text-yellow-400 hover:text-yellow-200 underline"
            >
              <Settings className="w-3.5 h-3.5" />
              {t('monitoring.go_to_config')}
            </button>
          </div>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
        <div className={`rounded-lg border p-5 ${systemVariant.card}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                {t('monitoring.servers_down')}
              </p>
              <p className={`text-4xl font-bold ${systemVariant.value}`}>
                {systemLoading ? '—' : systemDown}
              </p>
            </div>
            <Server className={`w-8 h-8 ${systemVariant.value} opacity-60`} />
          </div>
          {!systemLoading && systemDown === 0 && (
            <p className="text-xs text-green-500 mt-2 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> {t('monitoring.all_up')}
            </p>
          )}
        </div>

        <div className={`rounded-lg border p-5 ${serviceVariant.card}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                {t('monitoring.services_down')}
              </p>
              <p className={`text-4xl font-bold ${serviceVariant.value}`}>
                {serviceLoading ? '—' : serviceDown}
              </p>
            </div>
            <Cpu className={`w-8 h-8 ${serviceVariant.value} opacity-60`} />
          </div>
          {!serviceLoading && serviceDown === 0 && (
            <p className="text-xs text-green-500 mt-2 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> {t('monitoring.all_up')}
            </p>
          )}
        </div>
      </div>

      {/* Detail sections */}
      <div className="space-y-6">
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-gray-400" />
            <h2 className="text-base font-semibold text-gray-200">{t('monitoring.system_probes')}</h2>
            <span className="text-xs text-gray-500 font-mono ml-1">
              up&#123;job=&quot;{SYSTEM_JOB}&quot;&#125;
            </span>
            {!systemLoading && !systemError && (
              <span className={`ml-auto text-xs font-medium px-2 py-0.5 rounded-full ${
                systemDown === 0
                  ? 'bg-green-900/40 text-green-400'
                  : systemDown <= 5
                    ? 'bg-orange-900/40 text-orange-400'
                    : 'bg-red-900/40 text-red-400'
              }`}>
                {systemDown} {t('monitoring.down')}
              </span>
            )}
          </div>
          <ProbeSection
            upProbes={systemUpProbes}
            downProbes={systemDownProbes}
            loading={systemLoading}
            error={systemError}
            upLabel={t('monitoring.servers_up')}
            downLabel={t('monitoring.servers_down_list')}
          />
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Cpu className="w-4 h-4 text-gray-400" />
            <h2 className="text-base font-semibold text-gray-200">{t('monitoring.service_probes')}</h2>
            <span className="text-xs text-gray-500 font-mono ml-1">
              up&#123;job!=&quot;{SYSTEM_JOB}&quot;&#125;
            </span>
            {!serviceLoading && !serviceError && (
              <span className={`ml-auto text-xs font-medium px-2 py-0.5 rounded-full ${
                serviceDown === 0
                  ? 'bg-green-900/40 text-green-400'
                  : serviceDown <= 5
                    ? 'bg-orange-900/40 text-orange-400'
                    : 'bg-red-900/40 text-red-400'
              }`}>
                {serviceDown} {t('monitoring.down')}
              </span>
            )}
          </div>
          <ProbeSection
            upProbes={serviceUpProbes}
            downProbes={serviceDownProbes}
            loading={serviceLoading}
            error={serviceError}
            upLabel={t('monitoring.services_up')}
            downLabel={t('monitoring.services_down_list')}
          />
        </div>
      </div>
    </div>
  )
}
