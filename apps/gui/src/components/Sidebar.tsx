/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useTranslation } from 'react-i18next'
import { LayoutDashboard, Brain, Cog, Play, FileEdit, Settings, BookOpen, Package, Activity, List, Rocket, Server, ShieldCheck, Cloud } from 'lucide-react'
import { View } from '../App'
import { AnsibleInventoryInfo, RunHandle } from '../types'

interface SidebarProps {
  currentView: View
  onViewChange: (view: View) => void
  inventories: AnsibleInventoryInfo[]
  selectedInventory: string
  onInventoryChange: (filePath: string) => void
  configMissing: boolean
  activeDeployments: RunHandle[]
}

interface MenuItem {
  id: View
  label: string
  icon: React.ElementType
}

interface Section {
  label: string
  items: MenuItem[]
}

export default function Sidebar({ currentView, onViewChange, inventories, selectedInventory, onInventoryChange, configMissing, activeDeployments }: SidebarProps) {
  const { t, i18n } = useTranslation()

  const runningCount = activeDeployments.filter((d) => d.status === 'running').length

  const sections: Section[] = [
    {
      label: t('nav.infrastructure'),
      items: [
        { id: 'servers', label: t('nav.servers'), icon: Server },
        { id: 'dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
        { id: 'diagnostics', label: t('nav.diagnostics'), icon: ShieldCheck },
        { id: 'providers', label: t('nav.providers'), icon: Cloud },
        { id: 'configuration', label: t('nav.configuration'), icon: Settings },
        { id: 'services', label: t('nav.services'), icon: Package },
        { id: 'monitoring', label: t('nav.monitoring'), icon: Activity },
        { id: 'deployments', label: t('nav.deployments'), icon: Rocket },
      ],
    },
    {
      label: t('nav.ansible'),
      items: [
        { id: 'inventory', label: t('nav.inventory'), icon: List },
        { id: 'roles', label: t('nav.roles'), icon: Cog },
        { id: 'playbooks', label: t('nav.playbooks'), icon: BookOpen },
        { id: 'group-vars', label: t('nav.group_vars'), icon: FileEdit },
        { id: 'ansible-runs', label: t('nav.ansible_runs'), icon: Play },
      ],
    },
    {
      label: t('nav.ai_ollama'),
      items: [
        { id: 'models', label: t('nav.models'), icon: Brain },
      ],
    },
  ]

  const toggleLanguage = (): void => {
    const newLang = i18n.language === 'fr' ? 'en' : 'fr'
    i18n.changeLanguage(newLang)
    localStorage.setItem('language', newLang)
  }

  return (
    <div className="w-64 bg-gray-900 text-white flex flex-col">
      <div className="p-6 border-b border-gray-800">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Brain className="w-8 h-8 text-primary-400" />
          {t('app.name')}
        </h1>
        <p className="text-sm text-gray-400 mt-1">{t('app.subtitle')}</p>
      </div>

      {/* Inventory selector */}
      <div className="px-4 py-3 border-b border-gray-800">
        <select
          value={selectedInventory}
          onChange={(e: React.ChangeEvent<HTMLSelectElement>) => onInventoryChange(e.target.value)}
          className="w-full px-2 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-gray-300 focus:ring-1 focus:ring-primary-500 focus:border-transparent"
          disabled={configMissing}
        >
          {configMissing ? (
            <option value="">{t('sidebar.config_missing')}</option>
          ) : inventories.length === 0 ? (
            <option value="">{t('sidebar.no_inventories')}</option>
          ) : (
            <>
              <option value="">{t('sidebar.select_inventory')}</option>
              {inventories.map((inv: AnsibleInventoryInfo) => (
                <option
                  key={inv.file_path}
                  value={inv.file_path}
                  title={inv.files.map((f: string) => f.split('/').pop()).join(', ')}
                >
                  {inv.name}
                  {inv.organization && inv.organization !== inv.name ? ` (${inv.organization})` : ''}
                  {inv.files.length > 1 ? ` · ${t('sidebar.parc_files', { count: inv.files.length })}` : ''}
                </option>
              ))}
            </>
          )}
        </select>
      </div>

      <nav className="flex-1 p-4 overflow-y-auto">
        {sections.map((section: Section, sectionIndex: number) => (
          <div key={section.label} className={sectionIndex > 0 ? 'mt-4' : ''}>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-4 mb-2">
              {section.label}
            </p>
            <ul className="space-y-1">
              {section.items.map((item: MenuItem) => {
                const Icon = item.icon
                const isActive = currentView === item.id
                const isDeployments = item.id === 'deployments'
                return (
                  <li key={item.id}>
                    <button
                      onClick={() => onViewChange(item.id)}
                      className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors text-left ${
                        isActive
                          ? 'bg-primary-600 text-white'
                          : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                      }`}
                    >
                      <Icon className="w-5 h-5 shrink-0" />
                      <span className="font-medium flex-1">{item.label}</span>
                      {isDeployments && runningCount > 0 && (
                        <span className="flex items-center justify-center w-5 h-5 text-xs font-bold bg-yellow-500 text-gray-900 rounded-full shrink-0">
                          {runningCount}
                        </span>
                      )}
                    </button>
                  </li>
                )
              })}
            </ul>
            {sectionIndex < sections.length - 1 && (
              <div className="mt-4 border-t border-gray-800" />
            )}
          </div>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-800 space-y-3">
        <button
          onClick={toggleLanguage}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
        >
          <span>{t('sidebar.language')}</span>
          <span className="font-mono text-xs bg-gray-800 px-2 py-0.5 rounded">
            {i18n.language === 'fr' ? 'FR' : 'EN'}
          </span>
        </button>
        <div className="text-xs text-gray-500 px-3">{t('app.version')}</div>
      </div>
    </div>
  )
}
