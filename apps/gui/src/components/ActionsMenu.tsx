/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown } from 'lucide-react'
import { listActions } from '../lib/api'
import { ActionContext, ActionId, ActionSubject, ItemAction } from '../types'

interface ActionsMenuProps {
  subject: ActionSubject
  context: ActionContext
  /** Masque l'alimentation quand l'écran la porte déjà par ses propres boutons
   *  (`MachinePower`) : deux jeux de boutons pour la même action est un défaut. */
  hidePower?: boolean
  onAction: (id: ActionId) => void
}

const POWER: ActionId[] = ['start', 'stop', 'reboot']

/** Les actions d'un élément, telles que le cœur les décide.
 *
 *  Le TUI ouvre le même catalogue sur `espace` : ce qui est possible, ce qui ne
 *  l'est pas et POURQUOI. Une action indisponible reste listée, grisée, avec sa
 *  raison — une entrée absente ne dit pas si l'action n'existe pas ou si une
 *  condition manque. */
export function ActionsMenu({ subject, context, hidePower, onAction }: ActionsMenuProps): JSX.Element {
  const { t } = useTranslation()
  const [open, setOpen] = useState<boolean>(false)
  const [actions, setActions] = useState<ItemAction[]>([])

  // La clé sérialisée : le contexte est reconstruit à chaque rendu, son
  // identité ne dit rien de son contenu.
  const contextKey = JSON.stringify(context)
  useEffect(() => {
    listActions(subject, context).then(setActions).catch(() => setActions([]))
  }, [subject, contextKey])

  const shown = actions.filter((a: ItemAction) => !(hidePower && POWER.includes(a.id)))
  if (shown.length === 0) return <></>

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-gray-700 text-gray-300 hover:bg-gray-800"
      >
        {t('actions.title')}
        <ChevronDown size={12} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <ul className="absolute right-0 z-20 mt-1 w-72 rounded-lg border border-gray-700 bg-gray-900 shadow-xl py-1">
            {shown.map((a: ItemAction) => (
              <li key={a.id}>
                <button
                  disabled={!a.enabled}
                  title={a.reason ?? undefined}
                  onClick={() => { setOpen(false); onAction(a.id) }}
                  className={`w-full text-left px-3 py-1.5 text-sm ${
                    a.enabled
                      ? a.destructive ? 'text-amber-300 hover:bg-gray-800' : 'text-gray-200 hover:bg-gray-800'
                      : 'text-gray-600 cursor-not-allowed'
                  }`}
                >
                  <span>{t(`actions.${a.id}`, { defaultValue: a.label })}</span>
                  {!a.enabled && a.reason && (
                    <span className="block text-[11px] text-gray-600 font-normal">{a.reason}</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
