#!/bin/sh
# Signe les binaires avec une identité STABLE, pour que le trousseau les
# reconnaisse d'une compilation à l'autre.
#
# Sans cela, `cargo build` produit une signature « ad hoc » dérivée du CONTENU
# du binaire : chaque compilation en change, macOS y voit une application
# inconnue, et « Toujours autoriser » ne peut jamais tenir. D'où une demande
# d'autorisation du trousseau à chaque reconstruction.
#
# À FAIRE UNE FOIS, à la main — un certificat ne se crée pas sans interaction :
#   Trousseau d'accès → menu Assistant de certification → Créer un certificat…
#     Nom          : FleetForge Dev
#     Type         : Signature de code
#     Auto-signé   : oui (laisser les valeurs par défaut)
#
# Puis, après chaque compilation :
#   ./sign-dev.sh
#
# L'identité peut être changée par la variable IDENTITY. À défaut de
# « FleetForge Dev », le certificat créé sous l'ancien nom du projet
# (« InfraManager Dev ») est repris : il signe tout aussi bien.

set -e
if [ -z "$IDENTITY" ]; then
  IDENTITY="FleetForge Dev"
  if ! security find-identity -v -p codesigning | grep -q "$IDENTITY" &&
     security find-identity -v -p codesigning | grep -q "InfraManager Dev"; then
    IDENTITY="InfraManager Dev"
  fi
fi

if ! security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  echo "Identité « $IDENTITY » introuvable." >&2
  echo "La créer dans Trousseau d'accès (voir l'en-tête de ce script)." >&2
  exit 1
fi

for binary in \
  target/debug/fleetforge target/release/fleetforge \
  target/debug/fleetforge-web target/release/fleetforge-web
do
  [ -f "$binary" ] || continue
  codesign --force --sign "$IDENTITY" "$binary"
  echo "signé : $binary"
done
