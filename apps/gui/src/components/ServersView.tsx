/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Vue Serveurs — une carte par MACHINE.
 *
 * L'application ne connaissait que l'entrée d'inventaire. Or huit entrées
 * partagent `203.0.113.10` et sept `203.0.113.11` : c'est la machine
 * qu'on allume, qu'on scrute et qu'on paie. Cette vue la rend enfin visible.
 */

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Server as ServerIcon, RefreshCw, AlertCircle, Search } from 'lucide-react'
import {
  getFleet, getDiagnostics, machineControls, listAlertRules, listAnsibleRoles, listAnsiblePlaybooks,
} from '../lib/api'
import {
  Fleet, Server, Health, Finding, AnsibleHost, MachineControl, AlertRule, PlaybookLaunchConfig,
  AnsibleRole, AnsiblePlaybook, DeployLaunchConfig, ActionContext, ActionId,
} from '../types'
import { MachinePower } from './MachinePower'
import { AlertExclusions } from './AlertExclusions'
import { ActionsMenu } from './ActionsMenu'
import PickerModal, { PickItem } from './PickerModal'
import AnsibleDeployModal from './AnsibleDeployModal'
import PlaybookRunModal from './PlaybookRunModal'

interface ServersViewProps {
  selectedInventory: string
  configMissing: boolean
  onLaunchPlaybook: (config: PlaybookLaunchConfig) => void
  onLaunchDeploy: (config: DeployLaunchConfig) => void
  /** Descendre d'un cran : les services d'un hôte (même geste que `↵` dans le TUI). */
  onOpenServices: (host: string) => void
}

/** Jetons de statut. Mêmes états, mêmes couleurs que le TUI — c'est ce qui
 *  rend les deux vues superposables. `unknown` n'est jamais vert : l'absence
 *  de sonde est le défaut que la supervision existe pour éviter. */
const HEALTH_STYLE: Record<Health, { dot: string; text: string; ring: string; label: string }> = {
  up:       { dot: 'bg-green-400',  text: 'text-green-400',  ring: 'ring-green-500/30',  label: 'health_up' },
  degraded: { dot: 'bg-amber-400',  text: 'text-amber-400',  ring: 'ring-amber-500/30',  label: 'health_degraded' },
  down:     { dot: 'bg-red-400',    text: 'text-red-400',    ring: 'ring-red-500/30',    label: 'health_down' },
  unknown:  { dot: 'bg-gray-600',   text: 'text-gray-500',   ring: 'ring-gray-700/40',   label: 'health_unknown' },
}

export function machineLabel(server: Server): string {
  // Le port n'est montré que lorsqu'il distingue réellement deux machines
  // derrière une même adresse — sinon il alourdit tout un parc pour rien.
  return server.key.svcprobe_port === 9110
    ? server.key.address
    : `${server.key.address}:${server.key.svcprobe_port}`
}

function ServerCard({
  server, fleet, findings, selected, onSelect, t,
}: {
  server: Server
  fleet: Fleet
  findings: Finding[]
  selected: boolean
  onSelect: () => void
  t: (k: string) => string
}) {
  const style = HEALTH_STYLE[server.health]
  const label = machineLabel(server)

  const related = findings.filter((f) =>
    (f.subject.kind === 'server' && f.subject.id === label) ||
    (f.subject.kind === 'host' && server.hosts.includes(f.subject.id)),
  )
  const errors = related.filter((f) => f.severity === 'error').length

  return (
    <button
      onClick={onSelect}
      className={`group text-left w-full rounded-xl border bg-gray-900/60 p-4 transition-all
        hover:bg-gray-900 hover:border-gray-600
        ${selected ? `border-primary-600 ring-2 ${style.ring}` : 'border-gray-800'}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${style.dot}`} />
          <span className="font-mono text-sm text-gray-100 truncate">{label}</span>
        </div>
        {server.provider
          ? <span className="shrink-0 px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400 border border-gray-700">
              {server.provider}
            </span>
          /* Un `provider` absent est une faute d'inventaire, pas un blanc. */
          : <span className="shrink-0 px-2 py-0.5 rounded text-xs bg-amber-900/40 text-amber-300 border border-amber-700/50">
              {t('inventory.provider_missing')}
            </span>}
      </div>

      <div className="mt-3 flex items-center gap-3 text-xs">
        <span className={style.text}>{t(`servers.${style.label}`)}</span>
        <span className="text-gray-600">·</span>
        <span className="text-gray-500">
          {server.hosts.length} {t(server.hosts.length > 1 ? 'servers.hosts' : 'servers.host')}
        </span>
        {errors > 0 && (
          <>
            <span className="text-gray-600">·</span>
            <span className="text-red-400 flex items-center gap-1">
              <AlertCircle size={12} /> {errors}
            </span>
          </>
        )}
      </div>

      {/* Les hôtes co-localisés, la donnée que la vue existe pour montrer. */}
      <div className="mt-3 flex flex-wrap gap-1">
        {server.hosts.slice(0, 6).map((name: string) => {
          const host: AnsibleHost | undefined = fleet.hosts.find((h) => h.name === name)
          return (
            <span
              key={name}
              title={host?.ansible_roles.join(', ') || t('servers.base_only')}
              className="px-1.5 py-0.5 rounded text-[11px] font-mono bg-gray-800/80 text-gray-400 border border-gray-700/60"
            >
              {name}
            </span>
          )
        })}
        {server.hosts.length > 6 && (
          <span className="px-1.5 py-0.5 text-[11px] text-gray-600">
            +{server.hosts.length - 6}
          </span>
        )}
      </div>
    </button>
  )
}

function ServerDetail({ server, fleet, findings, control, onPowered, inventoryPath, rules, onLaunchPlaybook, contextFor, onAction, onOpenServices, t }: {
  server: Server
  fleet: Fleet
  findings: Finding[]
  /** Absent quand l'hébergeur n'est pas connecté, quand la machine n'a pas
   *  d'instance correspondante, ou quand son adresse est revendiquée par deux
   *  comptes — piloter au hasard serait pire que ne rien proposer. */
  control?: MachineControl
  onPowered: () => void
  inventoryPath: string
  rules: AlertRule[]
  onLaunchPlaybook: (config: PlaybookLaunchConfig) => void
  /** Contexte d'actions pour ces hôtes : les faits que le cœur ne peut pas lire seul. */
  contextFor: (hosts: string[], findings: number) => ActionContext
  onAction: (id: ActionId, hosts: string[]) => void
  onOpenServices: (host: string) => void
  t: (k: string) => string
}) {
  const label = machineLabel(server)
  const hosted = server.hosts
    .map((name: string) => fleet.hosts.find((h: AnsibleHost) => h.name === name))
    .filter((h: AnsibleHost | undefined): h is AnsibleHost => h !== undefined)
  const style = HEALTH_STYLE[server.health]

  const related = findings.filter((f) =>
    (f.subject.kind === 'server' && f.subject.id === label) ||
    (f.subject.kind === 'host' && server.hosts.includes(f.subject.id)),
  )

  return (
    <div className="space-y-5">
      <div>
        {/* Fil d'Ariane : le même chemin que dans l'en-tête du TUI. */}
        <p className="text-xs text-gray-600 mb-1">{fleet.organization} › {t('servers.title')}</p>
        <div className="flex items-start justify-between gap-3">
          <h3 className="font-mono text-lg text-gray-100">{label}</h3>
          <ActionsMenu
            subject="machine"
            context={contextFor(server.hosts, related.length)}
            hidePower={control !== undefined}
            onAction={(id: ActionId) => onAction(id, server.hosts)}
          />
        </div>
        <p className={`text-sm mt-1 ${style.text}`}>{t(`servers.${style.label}`)}</p>
      </div>

      {/* Piloter la machine depuis l'écran qui la liste. Sans cela, éteindre
          `proxy1` imposait d'aller dans Providers y retrouver la tenancy puis
          l'instance — refaire à la main le rapprochement déjà fait ici. */}
      {control && (
        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">
            {t('servers.power')}
          </h4>
          <MachinePower control={control} onDone={onPowered} />
        </div>
      )}

      <dl className="text-sm space-y-1.5">
        <div className="flex gap-3">
          <dt className="text-gray-500 w-28 shrink-0">{t('inventory.provider')}</dt>
          <dd className="text-gray-300">{server.provider ?? t('inventory.provider_missing')}</dd>
        </div>
        {server.ssh_ports.length > 0 && (
          <div className="flex gap-3">
            <dt className="text-gray-500 w-28 shrink-0">{t('servers.ssh_ports')}</dt>
            <dd className="text-gray-300 font-mono">{server.ssh_ports.join(', ')}</dd>
          </div>
        )}
      </dl>

      <div id="server-hosts">
        <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">
          {t('servers.hosted')} ({server.hosts.length})
        </h4>
        <div className="space-y-1.5">
          {server.hosts.map((name: string) => {
            const host: AnsibleHost | undefined = fleet.hosts.find((h) => h.name === name)
            return (
              <div key={name} className="flex items-center gap-3 text-sm">
                <button
                  onClick={() => onOpenServices(name)}
                  title={t('actions.view_services')}
                  className="font-mono text-gray-200 w-36 shrink-0 truncate text-left hover:text-primary-300"
                >
                  {name}
                </button>
                <span className="text-xs text-primary-400 truncate flex-1">
                  {host && host.ansible_roles.length > 0
                    ? host.ansible_roles.join(' ')
                    : <span className="text-gray-600">{t('servers.base_only')}</span>}
                </span>
                <ActionsMenu
                  subject="host"
                  context={contextFor([name], findings.filter((f) => f.subject.kind === 'host' && f.subject.id === name).length)}
                  hidePower={control !== undefined}
                  onAction={(id: ActionId) => onAction(id, [name])}
                />
              </div>
            )
          })}
        </div>
      </div>

      <div id="alert-exclusions">
        <AlertExclusions
          inventoryPath={inventoryPath}
          hosts={hosted}
          rules={rules}
          onSaved={onPowered}
          onLaunchPlaybook={onLaunchPlaybook}
        />
      </div>

      {related.length > 0 && (
        <div id="server-findings">
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">
            {t('servers.findings')} ({related.length})
          </h4>
          <div className="space-y-2">
            {related.map((f: Finding, i: number) => (
              <div
                key={`${f.rule}-${i}`}
                className={`text-xs rounded-lg border px-3 py-2 ${
                  f.severity === 'error'
                    ? 'bg-red-950/40 border-red-800/50 text-red-200'
                    : 'bg-amber-950/30 border-amber-800/40 text-amber-200'
                }`}
              >
                <span className="font-mono opacity-60 mr-2">{f.rule}</span>
                {f.message}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function ServersView({ selectedInventory, configMissing, onLaunchPlaybook, onLaunchDeploy, onOpenServices }: ServersViewProps) {
  const { t } = useTranslation()
  const [fleet, setFleet] = useState<Fleet | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [controls, setControls] = useState<MachineControl[]>([])
  const [rules, setRules] = useState<AlertRule[]>([])
  const [roles, setRoles] = useState<AnsibleRole[]>([])
  const [playbooks, setPlaybooks] = useState<AnsiblePlaybook[]>([])
  /** Choix en cours (rôle ou playbook), puis la modale de lancement qui suit. */
  const [picker, setPicker] = useState<{ kind: 'role' | 'playbook'; hosts: string[] } | null>(null)
  const [deploy, setDeploy] = useState<{ role: AnsibleRole; hosts: string[] } | null>(null)
  const [run, setRun] = useState<{ playbook: AnsiblePlaybook; hosts: string[] } | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = async (): Promise<void> => {
    if (!selectedInventory) {
      setFleet(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      // Le parc d'abord : il s'affiche sans attendre les diagnostics, qui
      // interrogent Prometheus et peuvent traîner.
      setFleet(await getFleet(selectedInventory))
      setFindings(await getDiagnostics(selectedInventory).catch(() => []))
      // Vide tant qu'aucun hébergeur n'est connecté : le rapprochement n'a
      // alors rien à quoi rapprocher. L'échec ne doit pas emporter le parc,
      // qui s'affiche très bien sans.
      setControls(await machineControls(selectedInventory).catch(() => []))
      setRules(await listAlertRules(selectedInventory).catch(() => []))
      setRoles(await listAnsibleRoles().catch(() => []))
      setPlaybooks(await listAnsiblePlaybooks().catch(() => []))
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [selectedInventory])

  const contextFor = (hosts: string[], findingCount: number): ActionContext => {
    const caps = currentControl?.capabilities
    return {
      power: currentControl && caps
        ? {
            can_start: caps.start && currentControl.state !== 'running',
            can_stop: (caps.stop || caps.stop_graceful) && currentControl.state !== 'stopped',
            can_reboot: caps.reboot || caps.reboot_graceful,
          }
        : null,
      has_roles: roles.length > 0,
      has_playbooks: playbooks.length > 0,
      findings: findingCount,
      can_remove: false,
      can_purge: false,
      marked: hosts.length,
    }
  }

  const scrollTo = (id: string): void => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const handleAction = (id: ActionId, hosts: string[]): void => {
    switch (id) {
      case 'deploy_role': setPicker({ kind: 'role', hosts }); break
      case 'run_playbook': setPicker({ kind: 'playbook', hosts }); break
      case 'exempt_alert': scrollTo('alert-exclusions'); break
      case 'view_findings': scrollTo('server-findings'); break
      case 'view_hosts': scrollTo('server-hosts'); break
      case 'view_services': if (hosts[0]) onOpenServices(hosts[0]); break
      // L'alimentation a ses propres boutons quand la machine est pilotable.
      default: break
    }
  }

  /** Rôles de la famille de l'hôte en tête : ce sont eux qu'on vient chercher. */
  const roleItems = (hosts: string[]): PickItem[] => {
    const families = new Set(
      hosts.flatMap((h: string) => fleet?.hosts.find((x: AnsibleHost) => x.name === h)?.ansible_roles ?? []),
    )
    const relevant = (name: string): boolean => [...families].some((f: string) => name.startsWith(`${f}-`))
    return roles
      .map((r: AnsibleRole): PickItem => ({
        value: r.name, label: r.name, detail: r.category, highlight: relevant(r.name),
      }))
      .sort((a: PickItem, b: PickItem) => Number(b.highlight) - Number(a.highlight))
  }

  const servers = useMemo((): Server[] => {
    if (!fleet) return []
    const q = query.trim().toLowerCase()
    if (!q) return fleet.servers
    return fleet.servers.filter((s: Server) =>
      s.key.address.toLowerCase().includes(q) ||
      (s.provider ?? '').toLowerCase().includes(q) ||
      s.hosts.some((h: string) => h.toLowerCase().includes(q)),
    )
  }, [fleet, query])

  const current = useMemo((): Server | null => {
    if (!fleet) return null
    return fleet.servers.find((s: Server) => machineLabel(s) === selected) ?? servers[0] ?? null
  }, [fleet, servers, selected])

  // L'identité d'une MACHINE est `(adresse, port svcprobe)` : l'adresse seule
  // fusionnerait `hub` et `nuc`, deux machines derrière un même NAT.
  const currentControl = useMemo((): MachineControl | undefined => {
    if (!current) return undefined
    return controls.find(
      (c: MachineControl) =>
        c.key.address === current.key.address &&
        c.key.svcprobe_port === current.key.svcprobe_port,
    )
  }, [controls, current])

  if (configMissing) {
    return <div className="p-8 text-gray-500">{t('common.config_missing')}</div>
  }
  if (!selectedInventory) {
    return <div className="p-8 text-gray-500">{t('inventory.no_inventory_selected')}</div>
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl text-gray-100 flex items-center gap-2">
            <ServerIcon size={20} className="text-primary-400" />
            {t('servers.title')}
          </h2>
          {fleet && (
            <p className="text-sm text-gray-500 mt-1">
              {fleet.servers.length} {t('servers.machines')} · {fleet.hosts.length} {t('servers.hosts')}
              <span className="text-gray-600"> — {t('servers.subtitle')}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('common.search')}
              className="pl-9 pr-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder:text-gray-600 focus:ring-2 focus:ring-primary-500"
            />
          </div>
          <button
            onClick={load}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 disabled:opacity-40"
            title={t('common.refresh')}
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-800/50 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_22rem] gap-6">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 auto-rows-min">
          {servers.length === 0 && !loading && (
            <p className="text-gray-500 italic">{t('servers.none')}</p>
          )}
          {fleet && servers.map((s: Server) => (
            <ServerCard
              key={machineLabel(s)}
              server={s}
              fleet={fleet}
              findings={findings}
              selected={current !== null && machineLabel(current) === machineLabel(s)}
              onSelect={() => setSelected(machineLabel(s))}
              t={t}
            />
          ))}
        </div>

        <aside className="rounded-xl border border-gray-800 bg-gray-900/40 p-5 h-fit sticky top-8">
          {current && fleet
            ? <ServerDetail
                server={current}
                fleet={fleet}
                findings={findings}
                control={currentControl}
                onPowered={load}
                inventoryPath={selectedInventory}
                rules={rules}
                onLaunchPlaybook={onLaunchPlaybook}
                contextFor={contextFor}
                onAction={handleAction}
                onOpenServices={onOpenServices}
                t={t}
              />
            : <p className="text-sm text-gray-600">{t('servers.select_one')}</p>}
        </aside>
      </div>

      {picker?.kind === 'role' && (
        <PickerModal
          title={t('actions.pick_role')}
          items={roleItems(picker.hosts)}
          onClose={() => setPicker(null)}
          onPick={(name: string) => {
            const role = roles.find((r: AnsibleRole) => r.name === name)
            if (role) setDeploy({ role, hosts: picker.hosts })
            setPicker(null)
          }}
        />
      )}
      {picker?.kind === 'playbook' && (
        <PickerModal
          title={t('actions.pick_playbook')}
          items={playbooks.map((p: AnsiblePlaybook): PickItem => ({ value: p.path, label: p.label, detail: p.name }))}
          onClose={() => setPicker(null)}
          onPick={(path: string) => {
            const playbook = playbooks.find((p: AnsiblePlaybook) => p.path === path)
            if (playbook) setRun({ playbook, hosts: picker.hosts })
            setPicker(null)
          }}
        />
      )}
      {deploy && (
        <AnsibleDeployModal
          role={deploy.role}
          initialHosts={deploy.hosts}
          onClose={() => setDeploy(null)}
          onLaunch={onLaunchDeploy}
        />
      )}
      {run && (
        <PlaybookRunModal
          playbook={run.playbook}
          initialHosts={run.hosts}
          onClose={() => setRun(null)}
          onLaunch={onLaunchPlaybook}
        />
      )}
    </div>
  )
}
