/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Save, AlertCircle, X, FolderOpen, Link, Eye, EyeOff } from 'lucide-react'
import { pickDirectory } from '../lib/transport'
import {
  getInventoriesPath, setInventoriesPath,
  getPlaybooksPath, setPlaybooksPath,
  getPrometheusUrl, setPrometheusUrl,
  getPrometheusUser, setPrometheusUser,
  getPrometheusPassword, setPrometheusPassword,
} from '../lib/api'

interface ConfigurationViewProps {
  onSave?: () => void
}

export default function ConfigurationView({ onSave }: ConfigurationViewProps) {
  const { t } = useTranslation()
  const [invPath, setInvPath] = useState('')
  const [pbPath, setPbPath] = useState('')
  const [promUrl, setPromUrl] = useState('')
  const [promUser, setPromUser] = useState('')
  const [promPassword, setPromPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async (): Promise<void> => {
    try {
      const [inv, pb, prom, user, pass] = await Promise.all([
        getInventoriesPath(),
        getPlaybooksPath(),
        getPrometheusUrl(),
        getPrometheusUser(),
        getPrometheusPassword(),
      ])
      setInvPath(inv)
      setPbPath(pb)
      setPromUrl(prom)
      setPromUser(user)
      setPromPassword(pass)
    } catch (err) {
      setError(String(err))
    }
  }

  /** Le sélecteur natif n'existe que dans l'application de bureau ; servi dans
   *  un navigateur, le chemin attendu est celui du SERVEUR et se saisit. */
  const browsePath = async (
    setter: (v: string) => void,
    current: string,
    title: string,
  ): Promise<void> => {
    const selected = await pickDirectory(title, current)
    if (selected) setter(selected)
  }

  const handleSave = async (): Promise<void> => {
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await Promise.all([
        setInventoriesPath(invPath),
        setPlaybooksPath(pbPath),
        setPrometheusUrl(promUrl),
        setPrometheusUser(promUser),
        setPrometheusPassword(promPassword),
      ])
      setSuccess(t('config.saved'))
      onSave?.()
    } catch (err) {
      setError(String(err))
    } finally {
      setSaving(false)
    }
  }

  const inputClass = "flex-1 px-3 py-2 bg-gray-900 border border-gray-600 text-gray-100 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent font-mono text-sm placeholder:text-gray-600"

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100">{t('config.title')}</h1>
        <p className="text-gray-400 mt-2">{t('config.subtitle')}</p>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 bg-red-900/30 border border-red-700 text-red-400 rounded-lg px-4 py-3">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span className="text-sm">{error}</span>
          <button onClick={() => setError(null)} className="ml-auto"><X className="w-4 h-4" /></button>
        </div>
      )}

      {success && (
        <div className="mb-4 flex items-center gap-2 bg-green-900/30 border border-green-700 text-green-400 rounded-lg px-4 py-3">
          <span className="text-sm">{success}</span>
          <button onClick={() => setSuccess(null)} className="ml-auto"><X className="w-4 h-4" /></button>
        </div>
      )}

      <div className="bg-gray-800 rounded-lg shadow-md border border-gray-700 p-6 max-w-2xl">
        <div className="space-y-6">

          {/* Inventories path */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <FolderOpen className="w-4 h-4 inline mr-2" />
              {t('config.inventories_path')}
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={invPath}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setInvPath(e.target.value)}
                className={inputClass}
                placeholder={t('config.path_placeholder')}
              />
              <button
                type="button"
                onClick={() => browsePath(setInvPath, invPath, t('config.inventories_path'))}
                className="flex items-center gap-1.5 px-3 py-2 border border-gray-600 rounded-lg text-sm text-gray-400 hover:bg-gray-700 transition-colors shrink-0"
                title={t('config.browse')}
              >
                <FolderOpen className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">{t('config.inventories_path_help')}</p>
          </div>

          {/* Playbooks path */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <FolderOpen className="w-4 h-4 inline mr-2" />
              {t('config.playbooks_path')}
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={pbPath}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPbPath(e.target.value)}
                className={inputClass}
                placeholder={t('config.path_placeholder')}
              />
              <button
                type="button"
                onClick={() => browsePath(setPbPath, pbPath, t('config.playbooks_path'))}
                className="flex items-center gap-1.5 px-3 py-2 border border-gray-600 rounded-lg text-sm text-gray-400 hover:bg-gray-700 transition-colors shrink-0"
                title={t('config.browse')}
              >
                <FolderOpen className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">{t('config.playbooks_path_help')}</p>
          </div>

          {/* Prometheus section */}
          <div className="pt-2 border-t border-gray-700 space-y-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide flex items-center gap-2">
              <Link className="w-4 h-4" />
              Prometheus
            </h2>

            {/* URL */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                {t('config.prometheus_url')}
              </label>
              <input
                type="text"
                value={promUrl}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPromUrl(e.target.value)}
                className={inputClass + ' w-full'}
                placeholder="https://monitoring-server:9090"
              />
              <p className="text-xs text-gray-500 mt-1">{t('config.prometheus_url_help')}</p>
            </div>

            {/* User + Password side by side */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  {t('config.prometheus_user')}
                </label>
                <input
                  type="text"
                  value={promUser}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPromUser(e.target.value)}
                  className={inputClass + ' w-full'}
                  placeholder={t('config.prometheus_user_placeholder')}
                  autoComplete="off"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  {t('config.prometheus_password')}
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={promPassword}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPromPassword(e.target.value)}
                    className={inputClass + ' w-full pr-10'}
                    placeholder="••••••••"
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
            <p className="text-xs text-gray-500">{t('config.prometheus_auth_help')}</p>
          </div>

          <div className="pt-4 border-t border-gray-700">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg text-sm hover:bg-primary-700 transition-colors disabled:opacity-40"
            >
              <Save className="w-4 h-4" />
              {saving ? t('common.saving') : t('common.save')}
            </button>
          </div>

        </div>
      </div>
    </div>
  )
}
