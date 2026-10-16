/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Play, CheckCircle, XCircle, Loader, Eye, EyeOff, AlertCircle, X, RefreshCw } from 'lucide-react'
import { getAnsibleRuns, getAnsibleRunOutput } from '../lib/api'
import { AnsibleRun } from '../types'

function StatusBadge({ status }: { status: AnsibleRun['status'] }) {
  const { t } = useTranslation()

  if (status === 'success') {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full bg-green-900/50 text-green-400">
        <CheckCircle className="w-3 h-3" />
        {t('ansible_runs.status_success')}
      </span>
    )
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full bg-red-900/50 text-red-400">
        <XCircle className="w-3 h-3" />
        {t('ansible_runs.status_failed')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full bg-yellow-900/50 text-yellow-400">
      <Loader className="w-3 h-3 animate-spin" />
      {t('ansible_runs.status_running')}
    </span>
  )
}

function formatDate(dateStr: string, locale: string) {
  try {
    return new Intl.DateTimeFormat(locale === 'fr' ? 'fr-FR' : 'en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(dateStr))
  } catch {
    return dateStr
  }
}

interface RunRowProps {
  run: AnsibleRun
}

function RunRow({ run }: RunRowProps) {
  const { t, i18n } = useTranslation()
  const [outputVisible, setOutputVisible] = useState(false)
  const [output, setOutput] = useState<string | null>(run.output || null)
  const [loadingOutput, setLoadingOutput] = useState(false)
  const [outputError, setOutputError] = useState<string | null>(null)

  const toggleOutput = async () => {
    if (outputVisible) {
      setOutputVisible(false)
      return
    }
    if (output) {
      setOutputVisible(true)
      return
    }
    if (!run.id) {
      setOutputVisible(true)
      return
    }
    setLoadingOutput(true)
    setOutputError(null)
    try {
      const fullOutput = await getAnsibleRunOutput(run.id)
      setOutput(fullOutput)
      setOutputVisible(true)
    } catch (err) {
      setOutputError(t('ansible_runs.loading_output'))
    } finally {
      setLoadingOutput(false)
    }
  }

  return (
    <>
      <tr className="border-t border-gray-700 hover:bg-gray-700 transition-colors">
        <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
          {formatDate(run.started_at, i18n.language)}
        </td>
        <td className="px-4 py-3 text-sm text-gray-200 font-mono max-w-[160px] truncate" title={run.inventory}>
          {run.inventory.split('/').pop() || run.inventory}
        </td>
        <td className="px-4 py-3 text-sm text-gray-400">
          <div className="flex flex-wrap gap-1">
            {run.roles.length > 0 ? run.roles.map((r) => (
              <span key={r} className="bg-blue-900/40 text-blue-400 text-xs px-2 py-0.5 rounded-full">{r}</span>
            )) : <span className="text-gray-600">—</span>}
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-gray-400">
          <div className="flex flex-wrap gap-1">
            {run.hosts.length > 0 ? run.hosts.map((h) => (
              <span key={h} className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded-full">{h}</span>
            )) : <span className="text-gray-600">—</span>}
          </div>
        </td>
        <td className="px-4 py-3">
          <StatusBadge status={run.status} />
        </td>
        <td className="px-4 py-3">
          <button
            onClick={toggleOutput}
            disabled={loadingOutput}
            className="inline-flex items-center gap-1 text-xs px-3 py-1.5 border border-gray-600 rounded-md text-gray-400 hover:bg-gray-700 transition-colors disabled:opacity-50"
          >
            {loadingOutput ? (
              <Loader className="w-3 h-3 animate-spin" />
            ) : outputVisible ? (
              <EyeOff className="w-3 h-3" />
            ) : (
              <Eye className="w-3 h-3" />
            )}
            {loadingOutput
              ? t('ansible_runs.loading_output')
              : outputVisible
              ? t('ansible_runs.hide_output')
              : t('ansible_runs.show_output')}
          </button>
        </td>
      </tr>
      {outputVisible && (
        <tr className="border-t border-gray-700">
          <td colSpan={6} className="px-4 pb-4 pt-0">
            {outputError ? (
              <div className="text-sm text-red-400 bg-red-900/30 border border-red-700 rounded-md px-3 py-2">
                {outputError}
              </div>
            ) : (
              <pre className="bg-black text-green-400 text-xs font-mono rounded-md p-4 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto leading-relaxed">
                {output || t('ansible_runs.no_runs')}
              </pre>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function AnsibleRunsView() {
  const { t } = useTranslation()
  const [runs, setRuns] = useState<AnsibleRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadRuns()
  }, [])

  const loadRuns = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getAnsibleRuns()
      setRuns(data)
    } catch (err) {
      setError(t('ansible_runs.no_runs'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-8">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">{t('ansible_runs.title')}</h1>
          <p className="text-gray-400 mt-2">{t('ansible_runs.subtitle')}</p>
        </div>
        <button
          onClick={loadRuns}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 border border-gray-600 rounded-lg text-sm text-gray-400 hover:bg-gray-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 bg-red-900/30 border border-red-700 text-red-400 rounded-lg px-4 py-3">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span className="text-sm">{error}</span>
          <button onClick={() => setError(null)} className="ml-auto">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {loading ? (
        <div className="text-center text-gray-500 py-12">
          <p className="text-sm">{t('common.loading')}</p>
        </div>
      ) : runs.length === 0 ? (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-10 text-center text-gray-500">
          <Play className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-sm">{t('ansible_runs.no_runs')}</p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-gray-900 border-b border-gray-700">
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.date')}</th>
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.inventory')}</th>
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.roles')}</th>
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.hosts')}</th>
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.status')}</th>
                  <th className="px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{t('ansible_runs.output')}</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run, index) => (
                  <RunRow key={run.id ?? index} run={run} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
