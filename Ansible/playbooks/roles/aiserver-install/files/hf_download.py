#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Télécharge UN fichier Hugging Face dans un volume Docker monté sur /models.

Déployé par `aiserver-install` — NE PAS ÉDITER SUR L'HÔTE. Exécuté dans un
conteneur Python jetable : l'hôte n'a besoin ni de pip ni de virtualenv.

Entrée par variables d'environnement (jamais par arguments, que `ps` rend
lisibles par tous les comptes) :
    HF_TOKEN       jeton (optionnel, obligatoire pour un dépôt « gated »)
    HF_REPO        dépôt, ex. black-forest-labs/flux.1-dev
    HF_FILE        nom du fichier dans le dépôt
    HF_SUBDIR      sous-répertoire de /models (vide : racine, cas llama.cpp)
    HF_DEST_NAME   nom final (alias `display_name`), défaut HF_FILE
    KEEP_ORIGINAL  "1" : garder aussi HF_FILE à côté de l'alias
"""

import os
import shutil

from huggingface_hub import hf_hub_download

MODELS = "/models"


def place(src, dest):
    """Lien dur si possible (même volume : aucun octet dupliqué), copie sinon."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.lexists(dest):
        os.remove(dest)
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)
    os.chmod(dest, 0o644)


def main():
    repo = os.environ["HF_REPO"]
    filename = os.environ["HF_FILE"]
    token = os.environ.get("HF_TOKEN") or None
    subdir = os.environ.get("HF_SUBDIR", "")
    dest_name = os.environ.get("HF_DEST_NAME") or filename
    keep_original = os.environ.get("KEEP_ORIGINAL") == "1"

    target_dir = os.path.join(MODELS, subdir)
    cache_dir = os.path.join(MODELS, ".cache")
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    path = os.path.realpath(
        hf_hub_download(repo_id=repo, filename=filename, token=token, cache_dir=cache_dir)
    )

    place(path, os.path.join(target_dir, dest_name))
    if keep_original and dest_name != filename:
        place(path, os.path.join(target_dir, filename))
    print(os.path.join(target_dir, dest_name))


if __name__ == "__main__":
    main()
