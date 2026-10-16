/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertCircle, X, Save, RotateCcw, Plus, Trash2, FileText, Lock} from 'lucide-react'
import { GroupVarEntry } from '../types'
import { listGroupVarsFiles, readGroupVarsFile, writeGroupVarsFile } from '../lib/api'

interface GroupVarsViewProps {
  configMissing: boolean
}

export default function GroupVarsView({ configMissing }: GroupVarsViewProps) {
  const { t } = useTranslation()
  const [files, setFiles] = useState<string[]>([])
  const [selectedFile, setSelectedFile] = useState<string>('')
  const [entries, setEntries] = useState<GroupVarEntry[]>([])
  const [originalEntries, setOriginalEntries] = useState<GroupVarEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    loadFiles()
  }, [])

  const loadFiles = async (): Promise<void> => {
    try {
      const result = await listGroupVarsFiles()
      setFiles(result)
    } catch (err) {
      setError(`${t('group_vars.load_error')} : ${err}`)
    }
  }

  const loadFile = useCallback(async (filename: string): Promise<void> => {
    if (!filename) return
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const result = await readGroupVarsFile(filename)
      setEntries(result)
      setOriginalEntries(JSON.parse(JSON.stringify(result)))
    } catch (err) {
      setError(`${t('group_vars.read_error')} : ${err}`)
    } finally {
      setLoading(false)
    }
  }, [t])

  const handleFileSelect = (filename: string): void => {
    setSelectedFile(filename)
    loadFile(filename)
  }

  const handleValueChange = (index: number, value: string): void => {
    setEntries(prev => {
      const updated = [...prev]
      updated[index] = { ...updated[index], value }
      return updated
    })
  }

  const handleKeyChange = (index: number, key: string): void => {
    setEntries(prev => {
      const updated = [...prev]
      updated[index] = { ...updated[index], key }
      return updated
    })
  }

  const handleAddEntry = (): void => {
    setEntries(prev => [...prev, { key: '', value: '', value_type: 'string' }])
  }

  const handleRemoveEntry = (index: number): void => {
    setEntries(prev => prev.filter((_, i) => i !== index))
  }

  const handleSave = async (): Promise<void> => {
    if (!selectedFile) return
    const emptyKeys = entries.filter(e => e.key.trim() === '')
    if (emptyKeys.length > 0) {
      setError(t('group_vars.empty_keys_error'))
      return
    }
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await writeGroupVarsFile(selectedFile, entries)
      setOriginalEntries(JSON.parse(JSON.stringify(entries)))
      setSuccess(t('group_vars.save_success'))
    } catch (err) {
      setError(`${t('group_vars.save_error')} : ${err}`)
    } finally {
      setSaving(false)
    }
  }

  const handleCancel = (): void => {
    setEntries(JSON.parse(JSON.stringify(originalEntries)))
    setError(null)
    setSuccess(null)
  }

  const hasChanges = JSON.stringify(entries) !== JSON.stringify(originalEntries)

  const isMultiline = (entry: GroupVarEntry): boolean => {
    return entry.value_type === 'list' || entry.value_type === 'map' || entry.value.includes('\n')
  }

  const inputCls = 'w-full px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent font-mono text-sm placeholder:text-gray-600'

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100">{t('group_vars.title')}</h1>
        <p className="text-gray-400 mt-2">{t('group_vars.subtitle')}</p>
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

      {success && (
        <div className="mb-4 flex items-center gap-2 bg-green-900/30 border border-green-700 text-green-400 rounded-lg px-4 py-3">
          <span className="text-sm">{success}</span>
          <button onClick={() => setSuccess(null)} className="ml-auto">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-300 mb-2">{t('group_vars.select_file')}</label>
        <select
          value={selectedFile}
          onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleFileSelect(e.target.value)}
          className="w-full max-w-md px-3 py-2 bg-gray-900 border border-gray-600 text-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="">{t('group_vars.select_placeholder')}</option>
          {files.map((file: string) => (
            <option key={file} value={file}>{file}</option>
          ))}
        </select>
      </div>

      {loading && <p className="text-gray-500">{t('common.loading')}</p>}

      {!loading && selectedFile && entries.length === 0 && (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-8 text-center text-gray-500">
          <FileText className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p>{t('group_vars.empty_file')}</p>
        </div>
      )}

      {!loading && selectedFile && entries.length > 0 && (
        <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700">
          <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-200">{selectedFile}</h2>
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">{t('group_vars.variables_count', { count: entries.length })}</span>
              {hasChanges && (
                <span className="text-xs bg-amber-900/50 text-amber-400 px-2 py-0.5 rounded-full">{t('group_vars.modified')}</span>
              )}
            </div>
          </div>

          <div className="divide-y divide-gray-700">
            {entries.map((entry: GroupVarEntry, index: number) => (
              <div key={index} className="px-6 py-4 flex gap-4 items-start group hover:bg-gray-700/30">
                <div className="w-1/3 shrink-0">
                  <input
                    type="text"
                    value={entry.key}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleKeyChange(index, e.target.value)}
                    className={inputCls}
                    placeholder={t('group_vars.variable_name_placeholder')}
                  />
                  <span className="text-xs text-gray-600 mt-1 block">{entry.value_type}</span>
                </div>
                <div className="flex-1">
                  {/* Valeur chiffrée par Ansible Vault : ni affichée, ni
                      modifiable. Le cœur refuse de la réécrire — l'éditer ici
                      détruirait le chiffrement sans rien signaler. */}
                  {entry.value_type === 'vault' ? (
                    <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-amber-800/40 bg-amber-950/20">
                      <Lock size={13} className="text-amber-400 shrink-0" />
                      <span className="text-sm text-amber-200/80">{t('group_vars.vaulted')}</span>
                      <code className="ml-auto text-[11px] text-gray-600">ansible-vault edit</code>
                    </div>
                  ) : isMultiline(entry) ? (
                    <textarea
                      value={entry.value}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => handleValueChange(index, e.target.value)}
                      rows={Math.min(10, Math.max(3, entry.value.split('\n').length + 1))}
                      className={`${inputCls} resize-y`}
                      placeholder={t('group_vars.variable_value_placeholder')}
                    />
                  ) : (
                    <input
                      type="text"
                      value={entry.value}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleValueChange(index, e.target.value)}
                      className={inputCls}
                      placeholder={t('group_vars.variable_value_placeholder')}
                    />
                  )}
                </div>
                <button
                  disabled={entry.value_type === 'vault'}
                  onClick={() => handleRemoveEntry(index)}
                  className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-900/30 rounded-lg transition-colors opacity-0 group-hover:opacity-100"
                  title={t('group_vars.delete_variable')}
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
            <button
              onClick={handleAddEntry}
              className="flex items-center gap-2 px-4 py-2 border border-gray-600 rounded-lg text-sm text-gray-400 hover:bg-gray-700 transition-colors"
            >
              <Plus className="w-4 h-4" />
              {t('group_vars.add_variable')}
            </button>

            <div className="flex items-center gap-3">
              <button
                onClick={handleCancel}
                disabled={!hasChanges}
                className="flex items-center gap-2 px-4 py-2 border border-gray-600 rounded-lg text-sm text-gray-400 hover:bg-gray-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <RotateCcw className="w-4 h-4" />
                {t('common.cancel')}
              </button>
              <button
                onClick={handleSave}
                disabled={!hasChanges || saving}
                className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg text-sm hover:bg-primary-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Save className="w-4 h-4" />
                {saving ? t('common.saving') : t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
