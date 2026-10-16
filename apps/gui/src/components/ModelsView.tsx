/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, RefreshCw, ShieldCheck, Cpu, Pencil, Trash2 } from 'lucide-react'
import { Model } from '../types'
import { addModel, deleteModel, getModels, updateModel } from '../lib/api'
import ModelModal from './ModelModal'

export default function ModelsView() {
  const { t } = useTranslation()
  const [models, setModels] = useState<Model[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [currentModel, setCurrentModel] = useState<Model | null>(null)
  const [processingId, setProcessingId] = useState<number | null>(null)

  useEffect(() => {
    loadModels()
  }, [])

  const loadModels = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getModels()
      setModels(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.error'))
    } finally {
      setLoading(false)
    }
  }

  const predefinedModels = useMemo(() => models.filter((m) => m.is_predefined), [models])
  const customModels = useMemo(() => models.filter((m) => !m.is_predefined), [models])

  const openCreateModal = () => { setCurrentModel(null); setIsModalOpen(true) }
  const openEditModal = (model: Model) => { setCurrentModel(model); setIsModalOpen(true) }

  const handleSave = async (model: Model) => {
    try {
      if (model.id) {
        await updateModel(model)
      } else {
        await addModel(model)
      }
      setIsModalOpen(false)
      await loadModels()
    } catch (err) {
      alert(`${t('common.error')}:\n\n${err instanceof Error ? err.message : t('common.error')}`)
    }
  }

  const handleDelete = async (model: Model) => {
    if (!model.id) return
    if (!confirm(`${t('common.delete')} "${model.name}" ?`)) return
    setProcessingId(model.id)
    try {
      await deleteModel(model.id)
      await loadModels()
    } catch (err) {
      alert(`${t('common.error')}:\n\n${err instanceof Error ? err.message : t('common.error')}`)
    } finally {
      setProcessingId(null)
    }
  }

  const StatCard = ({ label, value, icon: Icon, accent }: {
    label: string; value: number; icon: typeof Cpu; accent: string
  }) => (
    <div className="bg-gray-800 border border-gray-700 rounded-2xl p-5 flex items-center gap-4">
      <div className={`p-3 rounded-xl ${accent}`}>
        <Icon className="w-6 h-6 text-white" />
      </div>
      <div>
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-3xl font-bold text-gray-100">{value}</p>
      </div>
    </div>
  )

  const renderModelCard = (model: Model) => (
    <div
      key={model.id ?? model.name}
      className="bg-gray-800 border border-gray-700 rounded-2xl p-6 flex flex-col justify-between shadow-sm hover:shadow-md hover:border-gray-600 transition-all"
    >
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-2xl bg-primary-900/30 flex items-center justify-center text-2xl">
          {model.icon || '🧠'}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-lg font-semibold text-gray-100">{model.name}</h3>
            {model.requires_auth && (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-amber-400 bg-amber-900/50 px-2 py-1 rounded-full">
                <ShieldCheck className="w-3.5 h-3.5" /> {t('models.requires_auth')}
              </span>
            )}
            {model.is_predefined && (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-primary-400 bg-primary-900/50 px-2 py-1 rounded-full">
                {t('models.predefined')}
              </span>
            )}
          </div>
          <p className="text-sm text-gray-500">{model.ollama_name}</p>
        </div>
      </div>

      <p className="text-sm text-gray-400 mt-4 line-clamp-3">{model.description}</p>

      <div className="grid grid-cols-3 gap-3 mt-4 text-sm">
        <div className="rounded-xl bg-gray-900 p-3">
          <p className="text-gray-500">{t('models.size')}</p>
          <p className="font-semibold text-gray-200">
            {model.size_gb ? `${model.size_gb.toFixed(1)} GB` : '—'}
          </p>
        </div>
        <div className="rounded-xl bg-gray-900 p-3">
          <p className="text-gray-500">{t('models.parameters')}</p>
          <p className="font-semibold text-gray-200">{model.parameters || '—'}</p>
        </div>
        <div className="rounded-xl bg-gray-900 p-3">
          <p className="text-gray-500">{t('models.context')}</p>
          <p className="font-semibold text-gray-200">
            {model.context_window ? `${model.context_window} ${t('models.tokens')}` : '—'}
          </p>
        </div>
      </div>

      {!model.is_predefined && (
        <div className="mt-5 flex items-center gap-2">
          <button
            onClick={() => openEditModal(model)}
            className="flex items-center gap-1 text-sm text-gray-400 px-3 py-2 rounded-lg hover:bg-gray-700"
          >
            <Pencil className="w-4 h-4" /> {t('common.edit')}
          </button>
          <button
            onClick={() => handleDelete(model)}
            disabled={processingId === model.id}
            className="flex items-center gap-1 text-sm text-red-400 px-3 py-2 rounded-lg hover:bg-red-900/30 disabled:opacity-50"
          >
            <Trash2 className="w-4 h-4" /> {t('common.delete')}
          </button>
        </div>
      )}
    </div>
  )

  return (
    <div className="p-8 space-y-8">
      <div className="flex flex-wrap items-center gap-4 justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-primary-400 font-semibold">
            {t('models.subtitle')}
          </p>
          <h1 className="text-3xl font-bold text-gray-100">{t('models.title')}</h1>
        </div>
        <div className="flex gap-3">
          <button
            onClick={loadModels}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-700"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            {t('common.loading')}
          </button>
          <button
            onClick={openCreateModal}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary-600 text-white hover:bg-primary-700"
          >
            <Plus className="w-4 h-4" /> {t('models.add_model')}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <StatCard label={t('models.predefined')} value={predefinedModels.length} icon={Cpu} accent="bg-purple-500" />
        <StatCard label={t('models.custom')} value={customModels.length} icon={Plus} accent="bg-blue-500" />
        <StatCard label={t('models.total')} value={models.length} icon={RefreshCw} accent="bg-primary-600" />
      </div>

      {error && (
        <div className="rounded-xl border border-red-700 bg-red-900/30 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-12 text-center text-gray-500">
          {t('common.loading')}
        </div>
      ) : (
        <div className="space-y-8">
          <section>
            <h2 className="text-xl font-semibold text-gray-100 mb-4">{t('models.predefined_models')}</h2>
            {predefinedModels.length === 0 ? (
              <div className="rounded-2xl border border-gray-700 bg-gray-800 p-10 text-center text-gray-500">
                {t('models.no_custom')}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
                {predefinedModels.map(renderModelCard)}
              </div>
            )}
          </section>

          <section>
            <h2 className="text-xl font-semibold text-gray-100 mb-4">{t('models.custom_models')}</h2>
            {customModels.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-gray-700 bg-gray-900/50 p-10 text-center text-gray-500">
                {t('models.no_custom_desc')}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
                {customModels.map(renderModelCard)}
              </div>
            )}
          </section>
        </div>
      )}

      {isModalOpen && (
        <ModelModal
          model={currentModel}
          onClose={() => setIsModalOpen(false)}
          onSave={handleSave}
        />
      )}
    </div>
  )
}
