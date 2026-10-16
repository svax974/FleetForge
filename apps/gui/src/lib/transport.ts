/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Aiguillage de transport : application de bureau (Tauri) ou navigateur (HTTP).
 *
 * C'est le SEUL endroit qui sait où tourne le frontal. `api.ts` appelle `call`
 * sans le savoir, et les vues ne connaissent que `api.ts` — le même code React
 * sert donc les deux paquetages, sans branche conditionnelle disséminée.
 *
 * Les deux façades exposent volontairement la même surface : le serveur HTTP
 * lit les arguments dans la casse qu'`invoke` envoie déjà (`inventoryPath`,
 * `deployId`…), si bien qu'il n'y a rien à traduire ici.
 */

export type Args = Record<string, unknown>

/** Vrai dans l'application de bureau. Tauri 1.x injecte `__TAURI_IPC__`. */
export const isDesktop = (): boolean =>
  typeof window !== 'undefined' && '__TAURI_IPC__' in window

/** Racine de l'API HTTP. Relative : le serveur sert le frontal ET l'API. */
const API_BASE = '/api'

/**
 * Appelle une commande du cœur.
 *
 * L'import de Tauri est DYNAMIQUE : statique, il embarquerait la couche IPC
 * dans le paquet servi aux navigateurs, où elle ne peut rien faire.
 */
export const call = async <T>(command: string, args: Args = {}): Promise<T> => {
  if (isDesktop()) {
    const { invoke } = await import('@tauri-apps/api/tauri')
    return invoke<T>(command, args)
  }

  const response = await fetch(`${API_BASE}/${command}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  })

  const payload: unknown = await response.json().catch(() => null)

  if (!response.ok) {
    // Le cœur rend déjà un message lisible ; on le remonte tel quel plutôt que
    // « 400 Bad Request », qui ne dirait rien de la cause.
    const message =
      payload && typeof payload === 'object' && 'error' in payload
        ? String((payload as { error: unknown }).error)
        : `${command} : ${response.status} ${response.statusText}`
    throw new Error(message)
  }

  return payload as T
}

/**
 * Suit la sortie d'un run en direct. Rend la fonction de désabonnement.
 *
 * Côté navigateur le transport est un `EventSource`, avec deux différences
 * assumées par rapport à Tauri :
 *   - le serveur REJOUE d'abord la sortie déjà produite, ce qui rend
 *     l'abonnement tardif inoffensif ;
 *   - il émet un événement `end` en fin de run, sur lequel on ferme. Un flux
 *     SSE simplement terminé est rouvert par le navigateur, qui rejouerait
 *     alors toute la sortie, en boucle.
 */
export const subscribeToRun = async (
  runId: string,
  onLine: (line: string) => void,
): Promise<() => void> => {
  if (isDesktop()) {
    const { listen } = await import('@tauri-apps/api/event')
    return listen<string>(`ansible_output_${runId}`, (event) => onLine(event.payload))
  }

  const source = new EventSource(`${API_BASE}/events/${encodeURIComponent(runId)}`)
  source.onmessage = (event: MessageEvent<string>): void => onLine(event.data)
  source.addEventListener('end', () => source.close())
  return () => source.close()
}

/**
 * Sélection d'un répertoire.
 *
 * Le navigateur n'a pas de sélecteur de dossier utilisable ici : les chemins
 * qui nous intéressent sont ceux du SERVEUR, pas ceux du poste. La saisie
 * manuelle n'est donc pas un repli dégradé, c'est la seule chose qui ait un
 * sens — le serveur peut être sur une autre machine.
 */
export const pickDirectory = async (
  title: string,
  current: string,
): Promise<string | null> => {
  if (isDesktop()) {
    const { open } = await import('@tauri-apps/api/dialog')
    const selected = await open({ directory: true, multiple: false, title })
    return typeof selected === 'string' ? selected : null
  }

  const entered = window.prompt(`${title}\n\nChemin sur le serveur :`, current)
  return entered && entered.trim() ? entered.trim() : null
}
