"""Hôtes `disabled: true` : jamais déployés, qu'un groupe ou une liste les cible.

Le drapeau vit sur l'hôte d'inventaire. `play.sh` et le lanceur de l'application
le traduisent en `--limit` (le seul moyen de couvrir TOUS les plays sans les
toucher) ; le calcul est unique (`scripts/disabled-hosts.sh`).

Le test est de bout en bout, sans connexion : `--list-hosts` n'ouvre aucune
session, il ne fait qu'appliquer les motifs d'hôtes.
"""

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAY = os.path.join(ROOT, "play.sh")
HELPER = os.path.join(ROOT, "scripts", "disabled-hosts.sh")
HAS_TOOLS = shutil.which("ansible-playbook") and shutil.which("ansible-inventory")

INVENTORY = textwrap.dedent(
    """\
    all:
      children:
        web3c:
          children:
            proxies:
              hosts:
                proxy1:
                  ansible_host: 192.0.2.10
                proxy2:
                  ansible_host: 192.0.2.11
                  disabled: true
                proxy3:
                  ansible_host: 192.0.2.12
    """
)

# Un playbook RÉEL, dont les plays ciblent le groupe `proxies` : `--list-hosts`
# n'exécute aucune tâche et n'ouvre aucune session, il n'applique que les motifs.
PLAYBOOK = "deploy-proxy.yml"


@unittest.skipUnless(HAS_TOOLS, "ansible-playbook / ansible-inventory absents")
class DisabledHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="disabled-hosts-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.inventory = os.path.join(self.tmp, "inventories", "web3c_inventory.yml")
        os.makedirs(os.path.dirname(self.inventory))
        with open(self.inventory, "w", encoding="utf-8") as handle:
            handle.write(INVENTORY)

    def helper(self):
        out = subprocess.run([HELPER, self.inventory], capture_output=True, text=True, check=True)
        return out.stdout.split()

    def hosts(self, *arguments):
        """Hôtes retenus par un run `--list-hosts` (aucune connexion)."""
        # `play.sh` vit à la racine du dépôt ; on lui donne l'inventaire temporaire.
        out = subprocess.run(
            [PLAY, "--inventory", self.inventory, PLAYBOOK, *arguments, "--list-hosts"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        # `deploy-proxy.yml` a plusieurs plays : on compare l'ENSEMBLE des hôtes
        # retenus, pas la liste répétée par play.
        kept = set()
        for line in out.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("proxy"):
                kept.add(stripped)
        return sorted(kept)

    def test_the_helper_names_the_disabled_hosts(self):
        self.assertEqual(self.helper(), ["proxy2"])

    def test_the_play_never_targets_a_disabled_host(self):
        self.assertEqual(self.hosts(), ["proxy1", "proxy3"])

    def test_a_caller_limit_keeps_its_hosts_and_still_excludes_the_disabled_one(self):
        self.assertEqual(self.hosts("--limit", "proxy1"), ["proxy1"])
        self.assertEqual(self.hosts("--limit", "proxy1,proxy3"), ["proxy1", "proxy3"])

    def test_targeting_a_disabled_host_alone_deploys_nothing(self):
        # Plus aucun hôte : Ansible refuse le run (« no hosts to target »). Un échec
        # visible vaut mieux qu'un succès qui n'a rien déployé.
        out = subprocess.run(
            [PLAY, "--inventory", self.inventory, PLAYBOOK, "--limit", "proxy2", "--list-hosts"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("disabled ignoré", out.stderr)
        self.assertIn("no hosts to target", out.stderr)


if __name__ == "__main__":
    unittest.main()
