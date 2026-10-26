import { useState, useEffect, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import DashboardView from './components/DashboardView'
import ModelsView from './components/ModelsView'
import ConfigurationView from './components/ConfigurationView'
import RolesView from './components/RolesView'
import PlaybooksView from './components/PlaybooksView'
import AnsibleRunsView from './components/AnsibleRunsView'
import GroupVarsView from './components/GroupVarsView'
import ServicesView from './components/ServicesView'
import MonitoringView from './components/MonitoringView'
import InventoryView from './components/InventoryView'
import DeploymentsView from './components/DeploymentsView'
import ServersView from './components/ServersView'
import DiagnosticsView from './components/DiagnosticsView'
import ProvidersView from './components/ProvidersView'
import { subscribeToRun } from './lib/transport'
import { listAnsibleInventories, getSelectedInventory, setSelectedInventory, getInventoriesPath, runAnsibleDeploy, runAnsiblePlaybook, getActiveRuns } from './lib/api'
import { AnsibleInventoryInfo, RunHandle, DeployLaunchConfig, PlaybookLaunchConfig } from './types'

export type View = 'servers' | 'diagnostics' | 'providers' | 'dashboard' | 'configuration' | 'models' | 'roles' | 'playbooks' | 'ansible-runs' | 'group-vars' | 'services' | 'monitoring' | 'inventory' | 'deployments'

function App() {
  const [currentView, setCurrentView] = useState<View>('servers')
  const [inventories, setInventories] = useState<AnsibleInventoryInfo[]>([])
  const [selectedInventory, setSelectedInv] = useState('')
  const [configMissing, setConfigMissing] = useState(false)
  const [activeDeployments, setActiveDeployments] = useState<RunHandle[]>([])
  /** Hôte dont on affiche les services : le cran « hôte » du fil d'Ariane. */
  const [servicesHost, setServicesHost] = useState<string | null>(null)

  const loadInventories = useCallback(async (): Promise<void> => {
    try {
      const invPath = await getInventoriesPath()
      if (!invPath) {
        setConfigMissing(true)
        setInventories([])
        return
      }
      setConfigMissing(false)
      // Le cœur écarte lui-même un inventaire devenu introuvable : la valeur
      // rendue est toujours vide ou valide, il n'y a plus rien à réparer ici.
      const [list, selected] = await Promise.all([listAnsibleInventories(), getSelectedInventory()])
      setInventories(list)
      setSelectedInv(selected)
    } catch {
      setInventories([])
    }
  }, [])

  useEffect(() => {
    loadInventories()
    // Les runs vivent dans le cœur : on récupère ceux déjà en cours plutôt que
    // de repartir d'une liste vide à chaque montage.
    getActiveRuns().then(setActiveDeployments).catch(() => {})
  }, [loadInventories])

  const handleInventoryChange = async (filePath: string): Promise<void> => {
    setSelectedInv(filePath)
    await setSelectedInventory(filePath)
  }

  const handleViewChange = (view: View): void => {
    // Un clic dans la barre latérale ouvre la vue entière : le cran d'hôte ne
    // doit pas la laisser filtrée sans qu'on sache pourquoi.
    if (view === 'services') setServicesHost(null)
    setCurrentView(view)
  }

  const openServicesOf = (host: string): void => {
    setServicesHost(host)
    setCurrentView('services')
  }

  useEffect(() => {
    if (currentView !== 'configuration') {
      loadInventories()
    }
  }, [currentView, loadInventories])

  /**
   * Suit un run en direct.
   *
   * L'écoute est posée AVANT le lancement : l'inverse perdrait les premières
   * lignes, celles qui portent justement l'échec de connexion.
   */
  const track = useCallback(async (
    handle: RunHandle,
    launch: () => Promise<{ status: string; finished_at?: string }>,
  ): Promise<void> => {
    setActiveDeployments((prev) => [...prev.filter((d) => d.id !== handle.id), handle])
    setCurrentView('deployments')

    const unlisten = await subscribeToRun(handle.id, (line) => {
      setActiveDeployments((prev) =>
        prev.map((d) => (d.id === handle.id ? { ...d, output: [...d.output, line] } : d)),
      )
    })

    const settle = (status: RunHandle['status'], finishedAt?: string): void => {
      setActiveDeployments((prev) =>
        prev.map((d) =>
          d.id === handle.id
            ? { ...d, status, finished_at: finishedAt ?? new Date().toISOString() }
            : d,
        ),
      )
    }

    try {
      const result = await launch()
      settle(result.status as RunHandle['status'], result.finished_at)
    } catch {
      // Le cœur refuse aussi en amont (rôle sans hôte, variable manquante) :
      // ces rejets-là n'ont jamais lancé Ansible, mais restent des échecs.
      settle('failed')
    } finally {
      unlisten()
    }
  }, [])

  const launchDeploy = useCallback(async (config: DeployLaunchConfig): Promise<void> => {
    await track(
      {
        id: config.id,
        label: config.label,
        kind: 'role',
        roles: config.roles,
        hosts: config.hosts,
        status: 'running',
        output: [],
        started_at: new Date().toISOString(),
      },
      () => runAnsibleDeploy(config.id, config.inventoryPath, config.roles, config.hosts, config.extraVars, config.label),
    )
  }, [track])

  const launchPlaybook = useCallback(async (config: PlaybookLaunchConfig): Promise<void> => {
    await track(
      {
        id: config.id,
        label: config.label,
        kind: 'playbook',
        roles: [],
        hosts: config.displayHosts,
        status: 'running',
        output: [],
        started_at: new Date().toISOString(),
      },
      () => runAnsiblePlaybook(config.id, config.playbookPath, config.inventoryPath, config.limitHosts, config.extraVars, config.label),
    )
  }, [track])

  const dismissDeployment = useCallback((id: string): void => {
    setActiveDeployments((prev) => prev.filter((d) => d.id !== id))
  }, [])

  return (
    <div className="flex h-screen bg-gray-950">
      <Sidebar
        currentView={currentView}
        onViewChange={handleViewChange}
        inventories={inventories}
        selectedInventory={selectedInventory}
        onInventoryChange={handleInventoryChange}
        configMissing={configMissing}
        activeDeployments={activeDeployments}
      />
      <main className="flex-1 overflow-auto">
        {currentView === 'servers' && <ServersView selectedInventory={selectedInventory} configMissing={configMissing} onLaunchPlaybook={launchPlaybook} onLaunchDeploy={launchDeploy} onOpenServices={openServicesOf} />}
        {currentView === 'diagnostics' && <DiagnosticsView selectedInventory={selectedInventory} configMissing={configMissing} />}
        {currentView === 'providers' && <ProvidersView selectedInventory={selectedInventory} />}
        {currentView === 'dashboard' && <DashboardView onNavigate={setCurrentView} />}
        {currentView === 'configuration' && <ConfigurationView onSave={loadInventories} />}
        {currentView === 'models' && <ModelsView />}
        {currentView === 'roles' && <RolesView configMissing={configMissing} onLaunchDeploy={launchDeploy} />}
        {currentView === 'playbooks' && <PlaybooksView configMissing={configMissing} onLaunchPlaybook={launchPlaybook} />}
        {currentView === 'ansible-runs' && <AnsibleRunsView />}
        {currentView === 'group-vars' && <GroupVarsView configMissing={configMissing} />}
        {currentView === 'services' && <ServicesView onNavigate={setCurrentView} onLaunchDeploy={launchDeploy} selectedInventory={selectedInventory} hostFilter={servicesHost} onClearHostFilter={() => setServicesHost(null)} />}
        {currentView === 'monitoring' && <MonitoringView onNavigate={setCurrentView} />}
        {currentView === 'inventory' && <InventoryView selectedInventory={selectedInventory} configMissing={configMissing} />}
        {currentView === 'deployments' && <DeploymentsView deployments={activeDeployments} onDismiss={dismissDeployment} />}
      </main>
    </div>
  )
}

export default App
