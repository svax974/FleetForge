/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { getInventoryGroups, getFleet, machineControls } from '../lib/api'
import { AnsibleGroup, AnsibleHost, Fleet, MachineControl, Server } from '../types'
import { MachinePower } from './MachinePower'

interface InventoryViewProps {
  selectedInventory: string
  configMissing: boolean
}

export default function InventoryView({ selectedInventory, configMissing }: InventoryViewProps) {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<AnsibleGroup[]>([])
  const [fleet, setFleet] = useState<Fleet | null>(null)
  const [controls, setControls] = useState<MachineControl[]>([])
  /** Deux lectures du MÊME inventaire : par groupes Ansible, ou par machine.
   *  Le second axe est le seul qui montre que huit entrées partagent une
   *  adresse — ce que l'arbre de groupes disperse par construction. */
  const [axis, setAxis] = useState<'groups' | 'machines'>('groups')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = (): void => {
    if (!selectedInventory) {
      setGroups([])
      return
    }
    setLoading(true)
    setError(null)
    Promise.all([
      getInventoryGroups(selectedInventory),
      getFleet(selectedInventory).catch(() => null),
      // Vide tant qu'aucun hébergeur n'est connecté : son échec ne doit pas
      // emporter l'inventaire, qui s'affiche très bien sans.
      machineControls(selectedInventory).catch((): MachineControl[] => []),
    ])
      .then(([g, f, c]) => { setGroups(g); setFleet(f); setControls(c) })
      .catch((err: unknown) => setError(String(err)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [selectedInventory])

  const renderHosts = (hosts: AnsibleHost[]) => (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-gray-500 border-b border-gray-700">
          <th className="pb-2 pr-6 font-medium">{t('common.name')}</th>
          <th className="pb-2 pr-6 font-medium">{t('inventory.ip')}</th>
          <th className="pb-2 pr-6 font-medium">{t('inventory.provider')}</th>
          <th className="pb-2 font-medium">{t('common.type')}</th>
        </tr>
      </thead>
      <tbody>
        {hosts.length === 0 ? (
          <tr>
            <td colSpan={4} className="py-2 text-gray-500 italic">{t('inventory.no_hosts')}</td>
          </tr>
        ) : (
          hosts.map((host: AnsibleHost) => (
            <tr key={host.name} className="border-b border-gray-800 last:border-0">
              <td className="py-2 pr-6 font-mono text-gray-200">{host.name}</td>
              <td className="py-2 pr-6 font-mono text-gray-400">{host.ansible_host || '—'}</td>
              {/* `provider` est obligatoire : une absence est un défaut
                  d'inventaire, pas une donnée manquante anodine — d'où le
                  traitement visuel distinct du tiret des colonnes optionnelles. */}
              <td className="py-2 pr-6">
                {host.provider
                  ? <span className="text-gray-400">{host.provider}</span>
                  : <span className="text-amber-500">{t('inventory.provider_missing')}</span>}
              </td>
              <td className="py-2 text-gray-500">{host.server_type || '—'}</td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  )

  const renderGroup = (group: AnsibleGroup, depth: number = 0) => (
    <div key={group.name} className={depth > 0 ? 'ml-4 border-l border-gray-700 pl-4' : ''}>
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-primary-400 mb-2 flex items-center gap-2">
          <span className="bg-primary-900/40 border border-primary-700/50 rounded px-2 py-0.5">{group.name}</span>
          <span className="text-xs text-gray-500 font-normal">
            {group.hosts.length} {t('inventory.hosts').toLowerCase()}
          </span>
        </h3>
        <div className="bg-gray-800 rounded-lg border border-gray-700 px-4 py-3">
          {renderHosts(group.hosts)}
        </div>
      </div>
      {group.children.map((child: AnsibleGroup) => renderGroup(child, depth + 1))}
    </div>
  )

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100">{t('inventory.title')}</h1>
        <p className="text-gray-400 mt-2">{t('inventory.subtitle')}</p>
      </div>

      {configMissing && (
        <p className="text-yellow-400 text-sm">{t('common.config_required')}</p>
      )}

      {!configMissing && !selectedInventory && (
        <p className="text-gray-500 text-sm">{t('sidebar.select_inventory')}</p>
      )}

      {loading && (
        <p className="text-gray-400 text-sm">{t('common.loading')}</p>
      )}

      {error && (
        <p className="text-red-400 text-sm">{error}</p>
      )}

      {!loading && !error && groups.length === 0 && selectedInventory && (
        <p className="text-gray-500 text-sm">{t('inventory.no_groups')}</p>
      )}

      {!loading && !error && groups.length > 0 && (
        <>
          <div className="inline-flex rounded-lg border border-gray-700 overflow-hidden mb-5">
            {(['groups', 'machines'] as const).map((a) => (
              <button
                key={a}
                onClick={() => setAxis(a)}
                className={`px-4 py-1.5 text-sm transition-colors ${
                  axis === a ? 'bg-primary-700 text-white' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {t(`inventory.axis_${a}`)}
              </button>
            ))}
          </div>

          {axis === 'groups' ? (
            <div className="space-y-4">
              {groups.map((group: AnsibleGroup) => renderGroup(group))}
            </div>
          ) : (
            <div className="space-y-4">
              {fleet?.servers.map((server: Server) => (
                <div key={`${server.key.address}:${server.key.svcprobe_port}`}>
                  <h3 className="text-sm font-semibold text-primary-400 mb-2 flex items-center gap-2">
                    <span className="bg-primary-900/40 border border-primary-700/50 rounded px-2 py-0.5 font-mono">
                      {server.key.svcprobe_port === 9110
                        ? server.key.address
                        : `${server.key.address}:${server.key.svcprobe_port}`}
                    </span>
                    <span className="text-xs text-gray-500 font-normal">
                      {server.provider ?? t('inventory.provider_missing')} · {server.hosts.length} {t('inventory.hosts').toLowerCase()}
                    </span>
                  </h3>
                  {/* L'alimentation porte sur la MACHINE, qui est le niveau de
                      regroupement ici : huit entrées d'inventaire partagent
                      203.0.113.10, les éteindre une par une n'aurait aucun
                      sens. */}
                  {(() => {
                    const control = controls.find(
                      (c: MachineControl) =>
                        c.key.address === server.key.address &&
                        c.key.svcprobe_port === server.key.svcprobe_port,
                    )
                    return control ? (
                      <div className="mb-2">
                        <MachinePower control={control} onDone={load} />
                      </div>
                    ) : null
                  })()}
                  <div className="bg-gray-800 rounded-lg border border-gray-700 px-4 py-3">
                    {renderHosts(fleet.hosts.filter((h: AnsibleHost) => server.hosts.includes(h.name)))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
