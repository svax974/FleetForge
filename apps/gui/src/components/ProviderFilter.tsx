/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Filtre multi-sélection des hébergeurs (`provider`). Un `provider` absent
 * est une faute d'inventaire : il reste sélectionnable sous la valeur `''`.
 */

import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, Check } from 'lucide-react'

interface ProviderFilterProps {
  /** Hébergeurs présents dans le parc (`''` = non renseigné). */
  options: string[]
  selected: string[]
  onChange: (selected: string[]) => void
}

export function ProviderFilter({ options, selected, onChange }: ProviderFilterProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  const toggle = (value: string): void =>
    onChange(selected.includes(value) ? selected.filter((v: string) => v !== value) : [...selected, value])

  const label = (value: string): string => value || t('servers.provider_unset')
  const summary =
    selected.length === 0
      ? t('servers.provider_all')
      : selected.length <= 2
        ? selected.map(label).join(', ')
        : `${t('servers.provider_filter')} (${selected.length})`

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex items-center gap-2 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 hover:border-gray-600"
      >
        <span className="max-w-[12rem] truncate">{summary}</span>
        <ChevronDown size={14} className="text-gray-500" />
      </button>
      {open && (
        <div
          role="listbox"
          aria-multiselectable="true"
          className="absolute right-0 z-20 mt-1 min-w-[12rem] rounded-lg border border-gray-700 bg-gray-900 py-1 shadow-xl"
        >
          {options.map((value: string) => {
            const checked = selected.includes(value)
            return (
              <button
                key={value}
                type="button"
                role="option"
                aria-selected={checked}
                onClick={() => toggle(value)}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm text-gray-300 hover:bg-gray-800"
              >
                <span className={`flex h-4 w-4 items-center justify-center rounded border ${checked ? 'border-primary-500 bg-primary-600' : 'border-gray-600'}`}>
                  {checked && <Check size={12} className="text-white" />}
                </span>
                {label(value)}
              </button>
            )
          })}
          {selected.length > 0 && (
            <button
              type="button"
              onClick={() => onChange([])}
              className="w-full border-t border-gray-800 px-3 py-1.5 text-left text-xs text-gray-500 hover:text-gray-300"
            >
              {t('servers.provider_clear')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
