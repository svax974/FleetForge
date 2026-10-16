/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { Model } from '../types'

interface ModelModalProps {
  model: Model | null
  onClose: () => void
  onSave: (model: Model) => Promise<void> | void
}

const createEmptyModel = (): Model => ({
  name: '',
  ollama_name: '',
  description: '',
  size_gb: undefined,
  parameters: '',
  context_window: undefined,
  is_predefined: false,
  category: 'Personnalisé',
  requires_auth: false,
  icon: '✨',
})

const inputCls = 'w-full border border-gray-700 bg-gray-900 text-gray-100 rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-primary-500 placeholder:text-gray-600'

export default function ModelModal({ model, onClose, onSave }: ModelModalProps) {
  const { t } = useTranslation()
  const [form, setForm] = useState<Model>(model ? { ...model } : createEmptyModel())
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    setForm(model ? { ...model } : createEmptyModel())
  }, [model])

  const title = useMemo(
    () => (model ? t('model_modal.edit_title') : t('model_modal.add_title')),
    [model, t]
  )

  const handleChange = (field: keyof Model, value: string) => {
    setForm((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  const handleNumberChange = (field: keyof Model, value: string) => {
    setForm((prev) => ({
      ...prev,
      [field]: value === '' ? undefined : Number(value),
    }))
  }

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    const payload: Model = {
      ...form,
      description: form.description || undefined,
      parameters: form.parameters || undefined,
      category: form.category || undefined,
      icon: form.icon || undefined,
      is_predefined: model?.is_predefined ?? false,
    }

    setSubmitting(true)
    try {
      await onSave(payload)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 px-4">
      <div className="bg-gray-800 rounded-2xl shadow-2xl w-full max-w-3xl border border-gray-700">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <div>
            <p className="text-xs uppercase tracking-widest text-primary-400 font-semibold">
              {t('model_modal.category')}
            </p>
            <h2 className="text-2xl font-bold text-gray-100">{title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-full hover:bg-gray-700 transition-colors"
            aria-label={t('common.close')}
            disabled={submitting}
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">
                {t('model_modal.name')} *
              </label>
              <input
                className={inputCls}
                value={form.name}
                onChange={(e) => handleChange('name', e.target.value)}
                placeholder={t('model_modal.name_placeholder')}
                required
                disabled={submitting}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">
                {t('model_modal.ollama_name')} *
              </label>
              <input
                className={inputCls}
                value={form.ollama_name}
                onChange={(e) => handleChange('ollama_name', e.target.value)}
                placeholder={t('model_modal.ollama_name_placeholder')}
                required
                disabled={submitting || model?.is_predefined}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">{t('model_modal.category')}</label>
              <input
                className={inputCls}
                value={form.category || ''}
                onChange={(e) => handleChange('category', e.target.value)}
                placeholder={t('model_modal.category_placeholder')}
                disabled={submitting}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">{t('model_modal.icon')}</label>
              <input
                className={inputCls}
                value={form.icon || ''}
                onChange={(e) => handleChange('icon', e.target.value)}
                placeholder={t('model_modal.icon_placeholder')}
                maxLength={2}
                disabled={submitting}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">
                {t('model_modal.size')}
              </label>
              <input
                type="number"
                className={inputCls}
                value={form.size_gb ?? ''}
                onChange={(e) => handleNumberChange('size_gb', e.target.value)}
                min="0"
                step="0.1"
                disabled={submitting}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">{t('model_modal.parameters')}</label>
              <input
                className={inputCls}
                value={form.parameters || ''}
                onChange={(e) => handleChange('parameters', e.target.value)}
                placeholder={t('model_modal.parameters_placeholder')}
                disabled={submitting}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">{t('model_modal.context_window')}</label>
              <input
                type="number"
                className={inputCls}
                value={form.context_window ?? ''}
                onChange={(e) => handleNumberChange('context_window', e.target.value)}
                min="0"
                step="256"
                disabled={submitting}
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-300">
              {t('model_modal.description')}
            </label>
            <textarea
              className={`${inputCls} min-h-[120px]`}
              value={form.description || ''}
              onChange={(e) => handleChange('description', e.target.value)}
              placeholder={t('model_modal.description_placeholder')}
              disabled={submitting}
            />
          </div>

          <div className="flex items-center justify-between rounded-xl border border-gray-700 px-4 py-3 bg-gray-900">
            <div>
              <p className="font-medium text-gray-100">{t('model_modal.requires_auth')}</p>
            </div>
            <label className="inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                className="sr-only"
                checked={form.requires_auth}
                onChange={(e) =>
                  setForm((prev) => ({
                    ...prev,
                    requires_auth: e.target.checked,
                  }))
                }
                disabled={submitting}
              />
              <span
                className={`w-12 h-6 flex items-center rounded-full p-1 transition-all ${
                  form.requires_auth ? 'bg-primary-600' : 'bg-gray-600'
                }`}
              >
                <span
                  className={`bg-white w-4 h-4 rounded-full shadow transform transition-transform ${
                    form.requires_auth ? 'translate-x-6' : ''
                  }`}
                />
              </span>
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-700 transition-colors"
              disabled={submitting}
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              className="px-5 py-2.5 rounded-lg bg-primary-600 text-white font-medium hover:bg-primary-700 transition-colors disabled:opacity-50"
              disabled={submitting || !form.name || !form.ollama_name}
            >
              {submitting ? t('common.loading') : t('common.save')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
