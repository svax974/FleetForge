/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'

export interface PickItem {
  value: string
  label: string
  detail?: string
  /** Mis en tête de liste : ce qu'on vient probablement chercher. */
  highlight?: boolean
}

interface PickerModalProps {
  title: string
  items: PickItem[]
  onPick: (value: string) => void
  onClose: () => void
}

/** Choix dans une liste filtrable — le sélecteur du TUI (`d`, `p`, `P`). */
export default function PickerModal({ title, items, onPick, onClose }: PickerModalProps): JSX.Element {
  const { t } = useTranslation()
  const [query, setQuery] = useState<string>('')

  const visible = useMemo((): PickItem[] => {
    const q = query.trim().toLowerCase()
    return items.filter(
      (i: PickItem) => !q || i.label.toLowerCase().includes(q) || (i.detail ?? '').toLowerCase().includes(q),
    )
  }, [items, query])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="w-[34rem] max-h-[80vh] flex flex-col rounded-xl border border-gray-700 bg-gray-900 shadow-2xl"
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
          <button onClick={onClose} className="p-1 hover:bg-gray-800 rounded"><X size={14} /></button>
        </div>
        <input
          autoFocus
          value={query}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
          onKeyDown={(e: React.KeyboardEvent) => {
            if (e.key === 'Enter' && visible[0]) onPick(visible[0].value)
            if (e.key === 'Escape') onClose()
          }}
          placeholder={t('common.search')}
          className="mx-4 mt-3 px-3 py-1.5 text-sm rounded border border-gray-700 bg-gray-950 text-gray-200"
        />
        <ul className="overflow-y-auto p-2 mt-2">
          {visible.length === 0 && <li className="px-3 py-2 text-sm text-gray-600">{t('actions.no_result')}</li>}
          {visible.map((i: PickItem) => (
            <li key={i.value}>
              <button
                onClick={() => onPick(i.value)}
                className="w-full flex items-baseline gap-3 px-3 py-1.5 rounded text-left hover:bg-gray-800"
              >
                <span className="font-mono text-sm text-gray-200 truncate">{i.label}</span>
                {i.detail && (
                  <span className={`text-xs truncate ${i.highlight ? 'text-primary-400' : 'text-gray-600'}`}>
                    {i.detail}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
