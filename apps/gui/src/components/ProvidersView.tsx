/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Vue Providers — hébergeurs, instances, et rapprochement avec l'inventaire.
 *
 * C'est ici que les deux moitiés se rejoignent : l'application connaissait les
 * hôtes sans jamais parler aux hébergeurs, le prototype listait les instances
 * sans rien savoir d'Ansible. La jointure se fait sur `(provider, adresse)`.
 */

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Cloud, RefreshCw, Power, RotateCw, Square, Link2, Unlink, Settings, Plus, Trash2, Globe, X, Pencil, Check } from 'lucide-react'
import {
  listProviders, reconnectProvider, disconnectProvider,
  forgetProvider, connectProvider, listInstances, powerInstance, reconcileFleet,
  runSessionAction, renameProvider,
} from '../lib/api'
import {
  ProviderStatus, AccountStatus, SessionAction, Instance, Reconciliation, PowerState,
  AuthField, AuthMethod, ServerProvider,
} from '../types'

interface ProvidersViewProps {
  selectedInventory: string
}

/**
 * Un hébergeur sait-il arrêter / redémarrer, quelle que soit la variante ?
 *
 * `capabilities.stop` désigne l'arrêt BRUTAL et `stop_graceful` l'arrêt propre :
 * ce sont deux capacités distinctes, et plusieurs hébergeurs n'en ont qu'une.
 * Ne tester que la première faisait disparaître le bouton chez GCP, qui n'a
 * que l'arrêt propre, et chez AWS pour le redémarrage.
 *
 * La variante envoyée reste la douce dès qu'elle existe — c'est le sens du
 * `graceful` passé à `handlePower`.
 */
const canStop = (p: ProviderStatus): boolean =>
  p.capabilities.stop || p.capabilities.stop_graceful

const canReboot = (p: ProviderStatus): boolean =>
  p.capabilities.reboot || p.capabilities.reboot_graceful

const STATE_STYLE: Record<PowerState, string> = {
  running: 'text-green-400',
  stopped: 'text-red-400',
  transitioning: 'text-amber-400',
  /** Jamais vert : un état inconnu affiché comme « arrêté » ferait relancer
   *  une machine qui tourne. */
  unknown: 'text-gray-500',
}

/** Formulaire d'identifiants. Les champs viennent du cœur, qui déclare aussi
 *  lesquels sont des secrets — le prototype le devinait en cherchant
 *  PASSWORD/SECRET/KEY dans le nom, et affichait le reste en clair.
 *
 *  Le cœur déclare également l'INDICATION de chaque champ et sa facultativité :
 *  sans elles, remplir « Consumer key » supposait de savoir déjà d'où elle
 *  vient, ce que le formulaire ne disait nulle part. */
function CredentialsForm({ provider, methods, initial, account, onDone, onCancel, t }: {
  provider: ServerProvider
  methods: AuthMethod[]
  /** Méthode présélectionnée : la détectée, sinon la première. */
  initial: AuthMethod
  /** Compte visé. `null` = création, dont le nom est à saisir. */
  account: string | null
  onDone: () => void
  onCancel: () => void
  t: (k: string) => string
}) {
  const [method, setMethod] = useState<AuthMethod>(initial)
  const [name, setName] = useState<string>(account ?? '')
  const [values, setValues] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  /** Un compte existant ne se renomme pas ici : changer le nom n'aurait pas
   *  renommé le compte, il en aurait créé un second en laissant le premier
   *  derrière, avec ses identifiants. Le renommage a son propre bouton (crayon),
   *  sur la ligne du compte. */
  const locked = account !== null

  // Un champ obligatoire vide part quand même chez l'hébergeur, qui répond par
  // un refus d'authentification : la cause serait alors cherchée du mauvais côté.
  const missing = method.fields.filter(
    (f: AuthField) => !f.optional && !(values[f.key] ?? '').trim(),
  )

  const submit = async (): Promise<void> => {
    if (missing.length > 0) return
    setBusy(true)
    setError(null)
    try {
      await connectProvider(provider, name, method.name, values)
      onDone()
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  // Changer de méthode repart d'un formulaire vide : les champs ne se
  // recouvrent que partiellement, et garder les anciens enverrait à
  // l'hébergeur des valeurs que la nouvelle méthode n'attend pas.
  const chooseMethod = (next: AuthMethod): void => {
    setMethod(next)
    setValues({})
    setError(null)
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-6">
      <div className="w-full max-w-lg max-h-full overflow-y-auto rounded-xl border border-gray-700 bg-gray-900 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-gray-100">
            {locked ? `${t('providers.configure')} · ${account}` : t('providers.add_account')}
          </h3>
          <button onClick={onCancel} className="text-gray-500 hover:text-gray-300">
            <X size={18} />
          </button>
        </div>

        {/* Choix de la méthode. Le cœur les rend dans l'ordre de préférence et
            marque celles qu'il détecte sur cette machine ; c'est une aide au
            choix, pas le choix lui-même — le prototype prenait methods[0]. */}
        {methods.length > 1 && (
          <div className="mb-4 space-y-1.5">
            {methods.map((m) => (
              <button
                key={m.name}
                onClick={() => chooseMethod(m)}
                className={`w-full text-left px-3 py-2 rounded-lg border text-sm transition-colors ${
                  m.name === method.name
                    ? 'border-primary-600 bg-primary-950/30 text-gray-100'
                    : 'border-gray-800 text-gray-400 hover:border-gray-700'
                }`}
              >
                <span className="flex items-center gap-2">
                  {m.label}
                  {m.detected && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded border border-green-800/50 bg-green-950/30 text-green-300">
                      {t('providers.detected')}
                    </span>
                  )}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* Nom du compte, seulement à la création : c'est lui qui distingue
            « ajouter une tenancy » de « corriger celle-ci ». */}
        {!locked && (
          <label className="block mb-3">
            <span className="text-xs text-gray-400">{t('providers.account_name')}</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="acme"
              className="mt-1 w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-200 font-mono focus:ring-2 focus:ring-primary-500"
            />
            <span className="mt-1 block text-[11px] leading-snug text-gray-500">
              {t('providers.account_name_hint')}
            </span>
          </label>
        )}

        <div className="space-y-3">
          {method.fields.map((field: AuthField) => (
            <label key={field.key} className="block">
              <span className="text-xs text-gray-400 flex items-center gap-1.5">
                {field.label}
                {field.optional && (
                  <span className="text-[10px] text-gray-600">{t('providers.optional')}</span>
                )}
              </span>
              <input
                type={field.secret ? 'password' : 'text'}
                autoComplete={field.secret ? 'new-password' : 'off'}
                value={values[field.key] ?? ''}
                onChange={(e) => setValues({ ...values, [field.key]: e.target.value })}
                placeholder={field.key}
                className="mt-1 w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-200 font-mono focus:ring-2 focus:ring-primary-500"
              />
              {field.hint && (
                <span className="mt-1 block text-[11px] leading-snug text-gray-500">
                  {field.hint}
                </span>
              )}
            </label>
          ))}
        </div>

        {error && (
          <p className="mt-3 text-xs text-red-300 bg-red-950/40 border border-red-800/50 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-2 text-sm text-gray-400 hover:text-gray-200">
            {t('common.cancel')}
          </button>
          <button
            onClick={submit}
            disabled={busy || missing.length > 0}
            title={missing.length > 0 ? missing.map((f: AuthField) => f.label).join(', ') : undefined}
            className="px-4 py-2 text-sm rounded-lg bg-primary-600 text-white hover:bg-primary-500 disabled:opacity-40"
          >
            {busy ? t('providers.connecting') : t('providers.connect')}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function ProvidersView({ selectedInventory }: ProvidersViewProps) {
  const { t } = useTranslation()
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [selected, setSelected] = useState<ServerProvider | null>(null)
  const [instances, setInstances] = useState<Instance[]>([])
  const [reconciliation, setReconciliation] = useState<Record<string, Reconciliation>>({})
  const [authMethod, setAuthMethod] = useState<AuthMethod | null>(null)
  /** Compte visé par le formulaire ouvert. `null` = création. */
  const [formAccount, setFormAccount] = useState<string | null>(null)
  /** Compte en cours de renommage, et le nom saisi. */
  const [renaming, setRenaming] = useState<{ from: string; value: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const load = async (): Promise<void> => {
    setError(null)
    try {
      const list = await listProviders()
      setProviders(list)
      if (!selected && list.length > 0) setSelected(list[0].kind)
    } catch (err: unknown) {
      setError(String(err))
    }
  }

  useEffect(() => { load() }, [])

  const current = providers.find((p) => p.kind === selected) ?? null

  const loadInstances = async (kind: ServerProvider): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      setInstances(await listInstances(kind))
      if (selectedInventory) {
        const pairs = await reconcileFleet(selectedInventory).catch(() => [])
        setReconciliation(Object.fromEntries(pairs))
      }
    } catch (err: unknown) {
      setError(String(err))
      setInstances([])
    } finally {
      setBusy(false)
    }
  }

  /** Ouvre le formulaire sur la méthode détectée, sinon la première.
   *  L'ordre vient du cœur et il est explicite — le prototype prenait
   *  `methods[0]` au hasard de l'ordre de détection.
   *
   *  `account` à `null` ouvre la création d'un compte. */
  const openForm = (p: ProviderStatus, account: string | null): void => {
    setFormAccount(account)
    setAuthMethod(p.auth_methods.find((m) => m.detected) ?? p.auth_methods[0] ?? null)
  }

  /** Rouvre TOUS les comptes enregistrés. Un compte en échec ne doit pas
   *  empêcher les autres — c'est toute la raison d'en avoir plusieurs — mais
   *  se taire le ferait passer pour connecté. */
  const handleConnect = async (): Promise<void> => {
    if (!current) return
    if (!current.has_saved_credentials) {
      openForm(current, current.accounts[0]?.name ?? null)
      return
    }

    setBusy(true)
    setError(null)
    try {
      // Seuls les comptes encore fermés : rouvrir ceux qui le sont déjà
      // relancerait leur connexion sans rien changer.
      const closed: string[] = current.accounts
        .filter((a) => a.has_saved_credentials && !a.connected)
        .map((a) => a.name)
      const failed: [string, string][] = []
      for (const name of closed) {
        try {
          await reconnectProvider(current.kind, name)
        } catch (err: unknown) {
          failed.push([name, String(err)])
        }
      }
      if (failed.length > 0) {
        setError(failed.map(([name, err]) => `${name} : ${err}`).join(' · '))
      }
      await load()
      await loadInstances(current.kind)
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const handleAccount = async (
    action: 'connect' | 'disconnect' | 'forget',
    name: string,
  ): Promise<void> => {
    if (!current) return
    setBusy(true)
    setError(null)
    try {
      if (action === 'connect') await reconnectProvider(current.kind, name)
      if (action === 'disconnect') await disconnectProvider(current.kind, name)
      if (action === 'forget') await forgetProvider(current.kind, name)
      await load()
      await loadInstances(current.kind)
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  /** Renomme un compte : identifiants et session le suivent, rien n'est recréé
   *  (changer le nom dans le formulaire de configuration en créerait un second). */
  const handleRename = async (): Promise<void> => {
    if (!current || !renaming) return
    setBusy(true)
    setError(null)
    try {
      await renameProvider(current.kind, renaming.from, renaming.value)
      setRenaming(null)
      await load()
      // Les instances déjà listées portent l'ancien nom de compte.
      await loadInstances(current.kind)
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  /** Le compte rendu est AFFICHÉ : `refresh` peut réussir sans rien changer
   *  d'utile, et un bouton qui ne dit rien laisse croire que c'est réglé. */
  const handleSession = async (name: string, action: string): Promise<void> => {
    if (!current) return
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const chosen = current.accounts
        .find((a) => a.name === name)?.session_actions
        .find((a) => a.name === action)
      if (chosen?.needs_local_browser) {
        setNotice(t('providers.session_browser'))
      }
      const message = await runSessionAction(current.kind, name, action)
      setNotice(t('providers.session_done').replace('{msg}', message))
      await load()
      await loadInstances(current.kind)
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const handlePower = async (
    instance: Instance,
    action: 'start' | 'stop' | 'reboot',
    graceful: boolean,
  ): Promise<void> => {
    // Le TUI met ces actions derrière une confirmation ; un clic sur une
    // icône de 13 px la mérite davantage encore. `start` en est dispensé :
    // il n'interrompt rien. Même geste que l'oubli d'identifiants ci-dessous.
    if (action !== 'start') {
      const label = t(`providers.cap_${action}${graceful ? '_graceful' : ''}`)
      const ask = t('providers.power_confirm')
        .replace('{action}', label)
        .replace('{name}', instance.name)
      if (!window.confirm(ask)) return
    }
    setBusy(true)
    setError(null)
    try {
      await powerInstance(instance.reference, action, graceful)
      if (selected) await loadInstances(selected)
    } catch (err: unknown) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const rec = selected ? reconciliation[selected] : undefined

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl text-gray-100 flex items-center gap-2">
            <Cloud size={20} className="text-primary-400" />
            {t('providers.title')}
          </h2>
          <p className="text-sm text-gray-500 mt-1">{t('providers.subtitle')}</p>
        </div>
        <button
          onClick={load}
          className="p-2 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600"
          title={t('common.refresh')}
        >
          <RefreshCw size={16} />
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-800/50 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      )}

      {notice && (
        <div className="mb-4 rounded-lg border border-green-800/50 bg-green-950/30 px-4 py-3 text-sm text-green-200">
          {notice}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[16rem_1fr] gap-6">
        <nav className="space-y-1.5 h-fit">
          {providers.map((p) => {
            const unavailable = !!p.missing_tool || !p.capabilities.list
            return (
              <button
                key={p.kind}
                onClick={() => { setSelected(p.kind); setInstances([]) }}
                className={`w-full text-left px-3 py-2.5 rounded-lg border transition-colors ${
                  selected === p.kind
                    ? 'border-primary-600 bg-primary-950/30'
                    : 'border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${
                    p.connected ? 'bg-green-400' : unavailable ? 'bg-gray-700' : 'bg-amber-400'
                  }`} />
                  <span className="text-sm text-gray-200">{p.label}</span>
                </div>
                <p className="text-[11px] text-gray-600 mt-1 ml-4">
                  {p.missing_tool
                    ? t('providers.tool_missing').replace('{tool}', p.missing_tool)
                    : !p.capabilities.list
                      ? t('providers.no_api')
                      : p.connected ? t('providers.connected') : t('providers.disconnected')}
                </p>
              </button>
            )
          })}
        </nav>

        <div className="space-y-6">
          {current && (
            <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-gray-100">{current.label}</h3>
                  {current.missing_tool && (
                    <p className="text-xs text-amber-300 mt-1">
                      {t('providers.tool_missing').replace('{tool}', current.missing_tool)}
                    </p>
                  )}
                </div>
                {current.capabilities.list && (
                  <div className="flex gap-2">
                    {/* Toujours accessible : des identifiants enregistrés se
                        changent (clé révoquée, projet différent), et
                        `handleConnect` reconnecte en silence sans jamais
                        rouvrir le formulaire. */}
                    <button
                      onClick={() => openForm(current, null)}
                      disabled={busy}
                      className="px-3 py-1.5 text-sm rounded-lg border border-gray-700 text-gray-300 hover:border-gray-600 disabled:opacity-40 flex items-center gap-1.5"
                    >
                      <Plus size={13} /> {t('providers.add_account')}
                    </button>
                    {current.connected && (
                      <button
                        onClick={() => loadInstances(current.kind)}
                        disabled={busy}
                        className="px-3 py-1.5 text-sm rounded-lg border border-gray-700 text-gray-300 hover:border-gray-600 disabled:opacity-40"
                      >
                        {t('providers.list_instances')}
                      </button>
                    )}
                    {/* Rouvre TOUS les comptes enregistrés d'un coup : c'est
                        l'intérêt d'en avoir plusieurs. */}
                    <button
                      onClick={handleConnect}
                      disabled={busy}
                      className="px-3 py-1.5 text-sm rounded-lg bg-primary-600 text-white hover:bg-primary-500 disabled:opacity-40 flex items-center gap-1.5"
                    >
                      <Link2 size={13} /> {t('providers.connect_all')}
                    </button>
                  </div>
                )}
              </div>

              {/* Comptes. Un hébergeur en porte plusieurs — deux tenancies
                  Oracle, deux profils AWS — et ils sont ouverts EN MÊME TEMPS :
                  n'en interroger qu'un ferait passer les machines des autres
                  pour « sans instance », c'est-à-dire pour un inventaire faux. */}
              {current.capabilities.list && current.accounts.length > 0 && (
                <ul className="mt-4 space-y-1.5">
                  {current.accounts.map((account: AccountStatus) => (
                    <li
                      key={account.name}
                      className="flex items-center gap-3 rounded-lg border border-gray-800 px-3 py-2"
                    >
                      <span
                        className={`h-2 w-2 rounded-full shrink-0 ${
                          account.connected
                            ? 'bg-green-400'
                            : account.has_saved_credentials ? 'bg-amber-400' : 'bg-gray-700'
                        }`}
                      />
                      {renaming?.from === account.name ? (
                        <input
                          autoFocus
                          value={renaming.value}
                          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                            setRenaming({ from: account.name, value: e.target.value })}
                          onKeyDown={(e: React.KeyboardEvent) => {
                            if (e.key === 'Enter') handleRename()
                            if (e.key === 'Escape') setRenaming(null)
                          }}
                          className="w-32 px-2 py-0.5 bg-gray-950 border border-gray-600 rounded text-sm text-gray-200 font-mono"
                        />
                      ) : (
                        <span className="text-sm text-gray-200 font-mono w-32 truncate">
                          {account.name}
                        </span>
                      )}
                      <span className="text-xs text-gray-500 flex-1">
                        {account.connected
                          ? `${instances.filter((i) => i.reference.account === account.name).length} ${t('providers.instances').toLowerCase()}`
                          : account.has_saved_credentials
                            ? t('providers.disconnected')
                            : t('providers.to_configure')}
                      </span>

                      <div className="flex gap-1 shrink-0">
                        {account.has_saved_credentials && !account.connected && (
                          <button
                            onClick={() => handleAccount('connect', account.name)}
                            disabled={busy}
                            title={t('providers.connect')}
                            className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-green-300 disabled:opacity-25"
                          >
                            <Link2 size={13} />
                          </button>
                        )}
                        {/* Commandes de session, déclarées par le cœur et
                            propres au compte : un profil OCI par clé n'a rien
                            à renouveler, un profil de session si. */}
                        {account.session_actions?.map((sa: SessionAction) => (
                          <button
                            key={sa.name}
                            onClick={() => handleSession(account.name, sa.name)}
                            disabled={busy}
                            title={`${sa.label} — ${sa.hint}`}
                            className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-primary-300 disabled:opacity-25"
                          >
                            {sa.needs_local_browser ? <Globe size={13} /> : <RefreshCw size={13} />}
                          </button>
                        ))}
                        {account.connected && (
                          <button
                            onClick={() => handleAccount('disconnect', account.name)}
                            disabled={busy}
                            title={t('providers.disconnect')}
                            className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200 disabled:opacity-25"
                          >
                            <Unlink size={13} />
                          </button>
                        )}
                        {account.has_saved_credentials && (
                          renaming?.from === account.name ? (
                            <>
                              <button
                                onClick={handleRename}
                                disabled={busy}
                                title={t('providers.rename_confirm')}
                                className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-green-300 disabled:opacity-25"
                              >
                                <Check size={13} />
                              </button>
                              <button
                                onClick={() => setRenaming(null)}
                                title={t('common.cancel')}
                                className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200"
                              >
                                <X size={13} />
                              </button>
                            </>
                          ) : (
                            <button
                              onClick={() => setRenaming({ from: account.name, value: account.name })}
                              disabled={busy}
                              title={t('providers.rename')}
                              className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200 disabled:opacity-25"
                            >
                              <Pencil size={13} />
                            </button>
                          )
                        )}
                        <button
                          onClick={() => openForm(current, account.name)}
                          disabled={busy}
                          title={t('providers.configure')}
                          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200 disabled:opacity-25"
                        >
                          <Settings size={13} />
                        </button>
                        {/* Oublier efface les identifiants, pas seulement la
                            session : confondre les deux rend la déconnexion
                            destructive. D'où la confirmation. */}
                        {account.has_saved_credentials && (
                          <button
                            onClick={() => {
                              if (window.confirm(t('providers.forget_confirm').replace('{account}', account.name))) {
                                handleAccount('forget', account.name)
                              }
                            }}
                            disabled={busy}
                            title={t('providers.forget')}
                            className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-red-300 disabled:opacity-25"
                          >
                            <Trash2 size={13} />
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}

              {/* Capacités déclarées : l'UI grise ce qui n'existe pas plutôt que
                  de proposer une action qui échouerait, ou pire, en ferait une autre. */}
              <div className="mt-4 flex flex-wrap gap-1.5">
                {([
                  ['list', current.capabilities.list],
                  ['start', current.capabilities.start],
                  ['stop', current.capabilities.stop],
                  ['stop_graceful', current.capabilities.stop_graceful],
                  ['reboot', current.capabilities.reboot],
                  ['reboot_graceful', current.capabilities.reboot_graceful],
                ] as [string, boolean][]).map(([name, allowed]) => (
                  <span
                    key={name}
                    className={`px-2 py-0.5 rounded text-[11px] border ${
                      allowed
                        ? 'border-green-800/50 bg-green-950/30 text-green-300'
                        : 'border-gray-800 text-gray-600 line-through'
                    }`}
                  >
                    {t(`providers.cap_${name}`)}
                  </span>
                ))}
              </div>
            </section>
          )}

          {instances.length > 0 && (
            <section className="rounded-xl border border-gray-800 overflow-hidden">
              <header className="px-4 py-3 border-b border-gray-800 text-sm text-gray-300">
                {t('providers.instances')} ({instances.length})
              </header>
              <ul className="divide-y divide-gray-800/60">
                {instances.map((inst) => (
                  <li key={inst.reference.id} className="px-4 py-3 flex items-center gap-4">
                    <span className={`text-xs w-24 shrink-0 ${STATE_STYLE[inst.state]}`}>
                      {inst.raw_state}
                    </span>
                    <span className="text-sm text-gray-200 font-mono w-40 truncate">{inst.name}</span>
                    {/* De quel compte vient l'instance : deux tenancies
                        peuvent avoir une machine du même nom. */}
                    {current && current.accounts.length > 1 && (
                      <span className="text-[11px] px-1.5 py-0.5 rounded border border-gray-700 text-gray-400 shrink-0">
                        {inst.reference.account}
                      </span>
                    )}
                    <span className="text-xs text-gray-500 flex-1 truncate">
                      {inst.shape} · {inst.addresses.join(' ') || '—'}
                      {inst.reference.zone && <span className="ml-2 text-gray-600">{inst.reference.zone}</span>}
                    </span>
                    <div className="flex gap-1 shrink-0">
                      {current?.capabilities.start && (
                        <button
                          onClick={() => handlePower(inst, 'start', false)}
                          disabled={busy || inst.state === 'running'}
                          title={t('providers.cap_start')}
                          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-green-300 disabled:opacity-25"
                        >
                          <Power size={13} />
                        </button>
                      )}
                      {current && canStop(current) && (
                        <button
                          onClick={() => handlePower(inst, 'stop', current.capabilities.stop_graceful)}
                          disabled={busy || inst.state === 'stopped'}
                          title={t(current.capabilities.stop_graceful ? 'providers.cap_stop_graceful' : 'providers.cap_stop')}
                          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-red-300 disabled:opacity-25"
                        >
                          <Square size={13} />
                        </button>
                      )}
                      {current && canReboot(current) && (
                        <button
                          onClick={() => handlePower(inst, 'reboot', current.capabilities.reboot_graceful)}
                          disabled={busy}
                          title={t(current.capabilities.reboot_graceful ? 'providers.cap_reboot_graceful' : 'providers.cap_reboot')}
                          className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-amber-300 disabled:opacity-25"
                        >
                          <RotateCw size={13} />
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Une adresse revendiquée par deux comptes : le rapprochement a
              tranché par ordre alphabétique. Le taire ferait piloter une
              tenancy en croyant piloter l'autre. */}
          {rec && rec.ambiguous?.length > 0 && (
            <section className="rounded-xl border border-red-800/50 bg-red-950/20 p-4">
              <h4 className="text-sm text-red-200">{t('providers.ambiguous')}</h4>
              <p className="text-xs text-red-300/70 mt-1">{t('providers.ambiguous_hint')}</p>
              <ul className="mt-3 space-y-1">
                {rec.ambiguous.map((a) => (
                  <li key={a.server.key.address} className="text-xs font-mono text-gray-300">
                    {a.server.key.address}
                    <span className="text-gray-500"> → {a.accounts.join(', ')}</span>
                    <span className="text-red-300"> (retenu : {a.accounts[0]})</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {rec && (rec.unmanaged.length > 0 || rec.unmatched.length > 0) && (
            <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {rec.unmanaged.length > 0 && (
                <div className="rounded-xl border border-amber-800/40 bg-amber-950/20 p-4">
                  <h4 className="text-sm text-amber-200">{t('providers.unmanaged')}</h4>
                  <p className="text-xs text-amber-300/70 mt-1">{t('providers.unmanaged_hint')}</p>
                  <ul className="mt-3 space-y-1">
                    {rec.unmanaged.map((i) => (
                      <li key={i.reference.id} className="text-xs font-mono text-gray-300">
                        {i.name} <span className="text-gray-600">{i.addresses.join(' ')}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {rec.unmatched.length > 0 && (
                <div className="rounded-xl border border-gray-700 bg-gray-900/40 p-4">
                  <h4 className="text-sm text-gray-200">{t('providers.unmatched')}</h4>
                  <p className="text-xs text-gray-500 mt-1">{t('providers.unmatched_hint')}</p>
                  <ul className="mt-3 space-y-1">
                    {rec.unmatched.map((s) => (
                      <li key={s.key.address} className="text-xs font-mono text-gray-300">
                        {s.key.address} <span className="text-gray-600">{s.hosts.join(' ')}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}
        </div>
      </div>

      {authMethod && current && (
        <CredentialsForm
          provider={current.kind}
          methods={current.auth_methods}
          initial={authMethod}
          account={formAccount}
          onDone={async () => { setAuthMethod(null); await load(); await loadInstances(current.kind) }}
          onCancel={() => setAuthMethod(null)}
          t={t}
        />
      )}
    </div>
  )
}
