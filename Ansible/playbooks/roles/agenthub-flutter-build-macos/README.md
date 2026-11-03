# agenthub-flutter-build-macos

Prérequis de **build** Flutter sur un serveur AgentHub macOS (Apple silicon ou Intel) : `flutter build
apk|appbundle|web|macos|ios`. Homebrew, sans connexion root : le rôle tourne **en tant que le compte du
runner** (`remote_user`) ; seules les étapes Xcode et le lien JVM utilisent sudo (`-K`).

## Ce qu'il fait
- Vérifie macOS et **Homebrew** (jamais installé ici : échec avec un message clair).
- **Xcode** : vérifié avec `xcodebuild -version`, jamais installé (Ansible ne peut pas). S'il manque, échec
  avec la marche à suivre (App Store / developer.apple.com). Puis `xcodebuild -license accept` (seulement si
  la licence ne l'est pas), `xcodebuild -runFirstLaunch` (seulement si nécessaire), liste informative des
  runtimes simulateur iOS (téléchargement optionnel : `agenthub_macos_download_ios_platform`).
- Homebrew : `openjdk@17` (+ lien dans `/Library/Java/JavaVirtualMachines`), `cocoapods`, cask
  `android-commandlinetools`.
- SDK Android dans **`~/Library/Android/sdk` du compte du runner** (pas de dossier partagé : un seul compte
  de runner sur un Mac de build, et Gradle peut y compléter ce qui manque), mêmes paquets et licences que le
  rôle Linux (variables `agenthub_android_*` communes).
- Flutter : cloné dans `agenthub_macos_flutter_dir` (`~/development/flutter`, canal `stable`) ou réutilisé
  s'il existe déjà ; `flutter config --android-sdk --jdk-dir` ; `flutter precache --ios --macos --android
  --web`.
- Bloc géré dans `~/.zprofile` (JAVA_HOME, ANDROID_HOME, PATH de Flutter) ; `flutter doctor -v` informatif,
  jamais bloquant.

## Hors périmètre
Installation d'Xcode, **certificats de signature et profils de provisionnement** (à fournir séparément :
trousseau du compte du runner, ou secrets du projet importés au moment du build), Windows/Linux (aucune
compilation croisée), émulateurs.

## Variables utiles
`agenthub_macos_home`, `agenthub_android_sdk_dir`, `agenthub_macos_flutter_dir`,
`agenthub_macos_flutter_channel`, `agenthub_macos_java_formula`, `agenthub_macos_link_system_jvm`,
`agenthub_macos_download_ios_platform`, `agenthub_macos_brew_bin`, `agenthub_android_platforms`,
`agenthub_android_build_tools`, `agenthub_android_extra_packages`.

## Lancer
Déclarer le groupe `agenthub_flutter_macos` dans l'inventaire (voir l'en-tête du playbook), puis :

    ./play.sh <parc> deploy-agenthub-flutter-build.yml --tags macos -K
