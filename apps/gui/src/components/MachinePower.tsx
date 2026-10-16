/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Power, Square, RotateCw } from 'lucide-react'
import { powerInstance } from '../lib/api'
import { MachineControl, PowerState } from '../types'

interface MachinePowerProps {
  control: MachineControl
  /** Rejoué après une action acceptée : l'état change côté hébergeur, et une
   *  vignette figée ferait croire que rien ne s'est passé. */
  onDone: () => void
}

const STATE_STYLE: Record<PowerState, string> = {
  running: 'text-green-400',
  stopped: 'text-red-400',
  transitioning: 'text-amber-400',
  unknown: 'text-gray-500',
}

/** Pilotage de l'alimentation d'une machine, depuis l'écran qui la liste.
 *
 *  Le même composant sert partout : les décisions — quelle action est possible,
 *  quelle variante est retenue — viennent du cœur via `MachineControl`, pas de
 *  l'écran. Deux écrans qui décideraient chacun finiraient par ne pas proposer
 *  la même chose sur la même machine. */
export function MachinePower({ control, onDone }: MachinePowerProps): JSX.Element {
  const { t } = useTranslation()
  const [busy, setBusy] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const caps = control.capabilities
  // `stop` est l'arrêt BRUTAL et `stop_graceful` l'arrêt propre : plusieurs
  // hébergeurs n'ont que l'un des deux. Ne tester que le premier effacerait
  // l'action chez GCP, qui ne sait que l'autre.
  const canStop = caps.stop || caps.stop_graceful
  const canReboot = caps.reboot || caps.reboot_graceful

  const run = async (
    action: 'start' | 'stop' | 'reboot',
    graceful: boolean,
    label: string,
  ): Promise<void> => {
    // Le nom montré est celui de l'instance CHEZ L'HÉBERGEUR, pas celui de
    // l'inventaire : c'est ce qui va s'éteindre, et les deux diffèrent souvent.
    const ask = t('servers.power_confirm')
      .replace('{action}', label)
      .replace('{name}', control.name)
    if (action !== 'start' && !window.confirm(ask)) return

    setBusy(true)
    setError(null)
    try {
      await powerInstance(control.instance, action, graceful)
      onDone()
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const button = 'p-1.5 rounded border border-gray-700 text-gray-400 disabled:opacity-25'

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <span className={`text-xs font-mono ${STATE_STYLE[control.state]}`}>
          {control.raw_state}
        </span>
        <span className="text-xs text-gray-500 font-mono truncate flex-1">
          {control.name}
          <span className="text-gray-600 ml-2">{control.instance.account}</span>
        </span>
        <div className="flex gap-1 shrink-0">
          {caps.start && (
            <button
              onClick={() => run('start', false, t('providers.cap_start'))}
              disabled={busy || control.state === 'running'}
              title={t('providers.cap_start')}
              className={`${button} hover:text-green-300`}
            >
              <Power size={13} />
            </button>
          )}
          {canStop && (
            <button
              onClick={() =>
                run(
                  'stop',
                  caps.stop_graceful,
                  t(caps.stop_graceful ? 'providers.cap_stop_graceful' : 'providers.cap_stop'),
                )
              }
              disabled={busy || control.state === 'stopped'}
              title={t(caps.stop_graceful ? 'providers.cap_stop_graceful' : 'providers.cap_stop')}
              className={`${button} hover:text-red-300`}
            >
              <Square size={13} />
            </button>
          )}
          {canReboot && (
            <button
              onClick={() =>
                run(
                  'reboot',
                  caps.reboot_graceful,
                  t(caps.reboot_graceful ? 'providers.cap_reboot_graceful' : 'providers.cap_reboot'),
                )
              }
              disabled={busy}
              title={t(caps.reboot_graceful ? 'providers.cap_reboot_graceful' : 'providers.cap_reboot')}
              className={`${button} hover:text-amber-300`}
            >
              <RotateCw size={13} />
            </button>
          )}
        </div>
      </div>
      {error && <p className="text-xs text-red-300">{error}</p>}
    </div>
  )
}
