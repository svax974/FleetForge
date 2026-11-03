# agenthub-flutter-build-linux

Prérequis de **build** Flutter sur un serveur AgentHub Debian/Ubuntu (x86_64), pour que le runner et les
comptes `agr-*` lancent `flutter build apk|appbundle|web|linux` sans interaction.

S'ajoute à `agenthub-install` (tâches `flutter.yml` : SDK Flutter partagé `agenthub_flutter_dir`,
scripts `/usr/local/bin/flutter|dart`, copies `~/.agenthub-flutter` des comptes `agr-*`, chaîne Linux
desktop) et se joue **après** lui. Il réutilise ses variables `agenthub_flutter_dir` et
`agenthub_flutter_user` (lues dans ses defaults, donc utilisable avec `--tags`) et ne modifie aucun de
ses fichiers.

## Ce qu'il installe
- JDK 17 headless (apt) ; `JAVA_HOME` = `/usr/lib/jvm/java-17-openjdk-<arch>`.
- Outils en ligne de commande Android (zip officiel, révision et sha256 épinglés), puis, via `sdkmanager`
  dans `agenthub_android_sdk_dir` (`/opt/android-sdk`) : `platform-tools`, `platforms;android-N`,
  `build-tools;V`, paquets supplémentaires. Licences acceptées sans interaction (équivalent de
  `flutter doctor --android-licenses`), seulement s'il en reste.
- SDK possédé par l'utilisateur du runner, lisible par tous, jamais modifiable par les autres.
  Conséquence : Gradle ne peut pas y télécharger de composant manquant ; l'ajouter aux listes de variables
  et rejouer le rôle.
- `/etc/profile.d/agenthub-android.sh` (JAVA_HOME, ANDROID_HOME, ANDROID_SDK_ROOT, PATH) pour les sessions de
  connexion. Les services systemd ne sont ni modifiés ni redémarrés : `flutter config --android-sdk
  --jdk-dir` est posé pour le runner et pour chaque compte `agr-*` disposant de sa copie de Flutter (un
  compte sans copie sera traité au passage suivant).
- `flutter precache --android --web --linux`, puis rafraîchissement des copies des comptes `agr-*`.
- Vérification finale : sdkmanager, adb, java présents ; `flutter doctor -v` affiché sans jamais échouer
  (Chrome / Android Studio absents sont normaux).
- Contrôle d'espace disque (`agenthub_android_min_free_gb`) avant le téléchargement.

## Hors périmètre
macOS/iOS (Xcode, un Mac : rôle `agenthub-flutter-build-macos`), Windows (hôte Windows), émulateur Android
(pas de /dev/kvm), signature de release Android (keystore fourni par les secrets du projet), Linux arm64
(pas de build-tools Android pour cette architecture : le rôle refuse).

## Variables utiles
`agenthub_android_sdk_dir`, `agenthub_android_platforms`, `agenthub_android_build_tools`,
`agenthub_android_extra_packages`, `agenthub_android_cmdline_tools_version` + `_sha256`,
`agenthub_android_java_package`, `agenthub_android_java_home`, `agenthub_android_min_free_gb`.

## Lancer
    ./play.sh web3c deploy-agenthub-flutter-build.yml --tags linux
