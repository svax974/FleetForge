/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader, CheckCircle, XCircle, X, Rocket, BookOpen, Cog } from 'lucide-react'
import { RunHandle } from '../types'

interface DeploymentsViewProps {
  deployments: RunHandle[]
  onDismiss: (id: string) => void
}

function DeploymentCard({ deployment, onDismiss }: { deployment: RunHandle; onDismiss: () => void }) {
  const { t } = useTranslation()
  const outputRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [deployment.output])

  const isRunning = deployment.status === 'running'
  const isSuccess = deployment.status === 'success'

  const elapsed = (): string => {
    const start = new Date(deployment.started_at).getTime()
    const end = deployment.finished_at ? new Date(deployment.finished_at).getTime() : Date.now()
    const secs = Math.floor((end - start) / 1000)
    if (secs < 60) return `${secs}s`
    return `${Math.floor(secs / 60)}m${secs % 60}s`
  }

  return (
    <div className={`bg-gray-800 border rounded-xl overflow-hidden shadow-lg ${
      isRunning ? 'border-yellow-600/50' : isSuccess ? 'border-green-600/50' : 'border-red-600/50'
    }`}>
      {/* Card header */}
      <div className={`flex items-center justify-between px-4 py-3 border-b ${
        isRunning ? 'border-yellow-600/30 bg-yellow-900/10' : isSuccess ? 'border-green-600/30 bg-green-900/10' : 'border-red-600/30 bg-red-900/10'
      }`}>
        <div className="flex items-center gap-3 min-w-0">
          {isRunning ? (
            <Loader className="w-4 h-4 text-yellow-400 animate-spin shrink-0" />
          ) : isSuccess ? (
            <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          ) : (
            <XCircle className="w-4 h-4 text-red-400 shrink-0" />
          )}

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {deployment.kind === 'playbook'
                ? <BookOpen className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                : <Cog className="w-3.5 h-3.5 text-primary-400 shrink-0" />
              }
              <p className="text-sm font-semibold text-gray-100 truncate">{deployment.label}</p>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              {deployment.hosts.join(', ')} · {elapsed()}
              {isRunning && <span className="ml-1 text-yellow-400">{t('deployments.running')}</span>}
            </p>
          </div>
        </div>

        {!isRunning && (
          <button
            onClick={onDismiss}
            className="p-1.5 text-gray-500 hover:text-gray-300 hover:bg-gray-700 rounded-lg transition-colors shrink-0 ml-2"
            aria-label={t('common.close')}
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Output terminal */}
      <pre
        ref={outputRef}
        className="text-xs font-mono p-4 overflow-y-auto max-h-72 text-gray-300 whitespace-pre-wrap bg-black/60 leading-relaxed"
      >
        {deployment.output.length > 0
          ? deployment.output.join('\n')
          : <span className="text-gray-600 italic">{t('deployments.waiting')}</span>}
      </pre>
    </div>
  )
}

export default function DeploymentsView({ deployments, onDismiss }: DeploymentsViewProps) {
  const { t } = useTranslation()

  const running = deployments.filter((d) => d.status === 'running')
  const done = deployments.filter((d) => d.status !== 'running')

  return (
    <div className="p-6 h-full overflow-auto">
      {/* Page header */}
      <div className="flex items-center gap-3 mb-6">
        <Rocket className="w-6 h-6 text-primary-400" />
        <div>
          <h1 className="text-2xl font-bold text-gray-100">{t('deployments.title')}</h1>
          <p className="text-sm text-gray-400">{t('deployments.subtitle')}</p>
        </div>
      </div>

      {deployments.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <Rocket className="w-12 h-12 text-gray-700 mb-4" />
          <p className="text-gray-400 font-medium">{t('deployments.empty')}</p>
          <p className="text-sm text-gray-600 mt-1">{t('deployments.empty_desc')}</p>
        </div>
      )}

      {running.length > 0 && (
        <section className="mb-6">
          <h2 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider mb-3">
            {t('deployments.in_progress', { count: running.length })}
          </h2>
          <div className="space-y-4">
            {running.map((d) => (
              <DeploymentCard key={d.id} deployment={d} onDismiss={() => onDismiss(d.id)} />
            ))}
          </div>
        </section>
      )}

      {done.length > 0 && (
        <section>
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
            {t('deployments.completed')}
          </h2>
          <div className="space-y-4">
            {done.map((d) => (
              <DeploymentCard key={d.id} deployment={d} onDismiss={() => onDismiss(d.id)} />
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
