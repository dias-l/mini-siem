# Rapport technique — Mini-SIEM

**Module Python · Bachelor Cybersécurité · 2026-2027**
**Société fictive : Atelier Boréal — Incident des 12 et 13 octobre 2026**

> Document à convertir en PDF (10 à 15 pages). Les champs entre crochets
> `[...]` sont à personnaliser avant le rendu final.

---

## 1. Introduction

L'entreprise fictive **Atelier Boréal** héberge son site web sur le serveur
`srv-web01`. Son équipe informatique soupçonne une attaque les 12 et 13 octobre
2026, mais les traces sont dispersées entre trois sources de logs hétérogènes
(SSH/sudo, serveur web Apache, pare-feu) représentant environ 5 400 lignes sur
48 heures.

L'objectif de ce projet est de développer un **SIEM simplifié** (*Security
Information and Event Management*) capable de :

1. centraliser et normaliser les trois sources dans un format commun ;
2. détecter automatiquement les comportements suspects (force brute, scan de
   ports, attaques web, IP malveillantes) ;
3. corréler ces indices pour révéler un scénario d'attaque complet ;
4. présenter des alertes exploitables via une API et un tableau de bord web.

Le SIEM doit répondre à deux questions : **que s'est-il passé sur le serveur**,
et **le serveur a-t-il été compromis ?**

**Composition du groupe.** Le projet a été réalisé par **[Votre nom]**
(`diasliams@gmail.com`) en autonomie. En l'absence de co-équipiers, l'ensemble
des quatre lots (collecte/normalisation, stockage/intégration,
détection/corrélation, tableau de bord) a été mené par le même auteur. Le dépôt
Git retrace l'avancement lot par lot.

---

## 2. Architecture

Le SIEM traite les données **de gauche à droite**, depuis les fichiers de logs
jusqu'aux alertes :

```
 Fichiers de logs                Normalisation            Stockage          Détection / Corrélation      Restitution
 ┌───────────────┐   parsers   ┌───────────────┐        ┌──────────┐       ┌──────────────────────┐    ┌──────────────┐
 │ auth.log      │ ─────────►  │               │        │          │       │ R1 force brute SSH   │    │ alertes.json │
 │ apache.log    │ ─────────►  │ Event (UTC)   │ ─────► │ SQLite   │ ────► │ R2 scan de ports     │ ─► │ API /api     │
 │ firewall.csv  │ ─────────►  │ format commun │        │ events + │       │ R3 attaques web      │    │ dashboard /  │
 └───────────────┘             └───────────────┘        │ alerts   │       │ R4 scan web          │    └──────────────┘
 ┌───────────────┐                                      └──────────┘       │ R5 réputation IP     │
 │ malicious_ips │ ───────────── threat intel ─────────────────────►       │ C1 compromission     │
 └───────────────┘                                                         │ C2 chaîne d'attaque  │
                                                                           └──────────────────────┘
```

### 2.1 Choix techniques

| Choix | Justification |
|---|---|
| **Architecture modulaire** (`siem/parsers`, `siem/detection`, `siem/storage`, `siem/dashboard`) | Chaque responsabilité est isolée et testable séparément (NF8). |
| **Dataclass `Event` unique** | Un seul modèle normalisé pour les trois sources simplifie la détection et l'export. |
| **SQLite** | Base embarquée sans serveur, requêtes SQL expressives, idéale pour un volume modeste. |
| **Configuration YAML** | Seuils, fenêtres, signatures et liste blanche externalisés, aucune valeur en dur (NF2). |
| **Flask + Jinja2** | Léger, échappement HTML automatique (protection XSS native, NF4). |
| **Graphique HTML/CSS côté serveur** | Aucune dépendance JavaScript externe, conforme à la liste de bibliothèques autorisées (NF1). |
| **Table de mois explicite** (`timeutils`) | Évite la dépendance de `strptime('%b')` à la locale du système (portabilité, NF7). |

### 2.2 Commandes (F10)

```
python main.py ingest      # collecte + normalisation + stockage
python main.py detect      # détection + corrélation
python main.py report      # export vers output/alertes.json
python main.py run         # les trois étapes à la suite
python main.py dashboard   # tableau de bord web (127.0.0.1:5000)
```

---

## 3. Normalisation des logs

### 3.1 Format d'événement commun

Toutes les sources produisent la même structure (un champ sans objet reste
`null`) :

`timestamp` (UTC), `source`, `event_type`, `raw`, `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `protocol`, `action`, `host`, `user`, `command`,
`http_method`, `url`, `http_status`, `bytes_sent`, `user_agent`.

### 3.2 Difficultés par source

**auth.log (SSH et sudo).**
- *Fuseau horaire* : heure locale du serveur (UTC+02:00) **sans année** ; l'année
  (2026) est fournie par la configuration, et la date est convertie en UTC.
- *Lignes à ignorer* : les lignes `CRON`, les sessions `pam_unix`, les
  `Connection closed` et surtout les lignes `Invalid user` seules (déjà comptées
  par la ligne `Failed password for invalid user` qui suit) ne sont pas des
  événements, mais ne sont pas non plus corrompues.
- *Fusion* : les deux variantes `Failed password for <user>` et `Failed password
  for invalid user <user>` sont unifiées par une expression régulière avec un
  groupe optionnel.

**apache_access.log (format combined).**
- *Fuseau horaire* : décalage indiqué dans chaque ligne (`+0200`).
- *Octets* : le champ peut valoir `-`, interprété comme 0.
- *URL* : conservée **encodée** telle quelle, puis décodée deux fois par la règle
  R3 (certaines charges sont double-encodées).
- *Requêtes invalides* : une requête réduite à `"-"` (ne contenant pas
  exactement méthode, URL et protocole) est comptée comme corrompue.

**firewall.csv (pare-feu).**
- *Fuseau horaire* : UTC (suffixe `Z`).
- *Validation* : 8 champs exactement, action `ALLOW`/`DENY`, IP et ports valides.
  L'en-tête CSV est ignoré sans être compté comme corrompu.

### 3.3 Tableau de synthèse (logs fournis)

| Source | Lignes lues | Événements | Lignes ignorées | Lignes corrompues |
|---|---:|---:|---:|---:|
| SSH / sudo (`auth.log`) | 364 | **190** | 171 | **3** |
| Web (`apache_access.log`) | 3 063 | **3 060** | 0 | **3** |
| Pare-feu (`firewall.csv`) | 1 950 | **1 946** | 1 | **3** |
| **Total** | **5 377** | **5 196** | 172 | **9** |

Les volumes d'événements correspondent exactement aux valeurs de référence du
document `formats_logs.md` (190 / 3 060 / 1 946), ce qui valide les analyseurs.
Par identité, pour chaque source : `lignes lues = événements + ignorées +
corrompues`.

Répartition par type d'événement : `firewall_allow` 1 775, `firewall_deny` 171,
`ssh_failed` 162, `ssh_success` 9, `sudo_command` 19, `web_request` 3 060.

### 3.4 Lignes corrompues rencontrées

| Source | Exemples de lignes corrompues |
|---|---|
| auth.log | `Oct 12 09:1` (tronquée), `\x00\x00\x00 corrupted entry`, `#### log rotated ####` |
| apache | `garbage line from log shipper`, ligne tronquée, requête `"-"` |
| firewall | `...Z,DENY,TCP` (3 champs), action invalide `DROP`, `not,a,valid,...` |

Dans tous les cas, la ligne est comptée puis **le traitement continue** (F1).

---

## 4. Détection et corrélation

### 4.1 Notion de rafale (fenêtre glissante)

Les règles R1, R2 et R4 reposent sur une **fenêtre glissante**, et non sur un
découpage minute par minute. Une attaque de 500 essais doit produire **une seule
alerte**, pas 496.

Algorithme (`siem/detection/burst.py`) :

1. **Formation** : une rafale démarre dès qu'une fenêtre glissante de
   `window_seconds` (bornes incluses) atteint le seuil. Elle contient alors tous
   les événements de cette fenêtre.
2. **Prolongation** : la rafale s'étend tant que l'écart entre un nouvel
   événement et le dernier événement de la rafale ne dépasse pas
   `window_seconds`.
3. **Nouvelle attaque** : au-delà de cet écart, une nouvelle rafale de la même IP
   produit une nouvelle alerte.

Le critère de seuil est injecté : comptage d'événements pour R1/R4, comptage de
**ports distincts** pour R2. `event_count` est le nombre d'événements de la
rafale.

### 4.2 Règles de détection

| N° | Menace | Condition | Sévérité | Configuration |
|---|---|---|---|---|
| **R1** | Force brute SSH | ≥ 5 `ssh_failed` d'une même IP en 60 s | HIGH | `threshold: 5`, `window: 60` |
| **R2** | Scan de ports | ≥ 15 ports distincts en `firewall_deny` d'une même IP en 60 s | MEDIUM | `distinct_ports: 15`, `window: 60` |
| **R3** | Attaque web | URL décodée (×2) correspondant à une signature `sqli` / `path_traversal` / `xss` ; une alerte par couple (IP, catégorie) | HIGH | signatures en config |
| **R4** | Scan web | ≥ 20 réponses HTTP 404 d'une même IP en 60 s | MEDIUM | `threshold: 20`, `window: 60` |
| **R5** | Réputation d'IP | IP présente dans `malicious_ips.csv`, toutes sources confondues ; une alerte par IP | MEDIUM | liste threat intel |

**Signatures R3.** Les expressions régulières (en configuration, insensibles à
la casse) sont volontairement ancrées pour éviter les faux positifs : par
exemple `union\s+select` et non le simple mot `union`. L'URL est décodée deux
fois avec `urllib.parse.unquote_plus`. Couverture minimale :
- *sqli* : `UNION SELECT`, `OR 1=1`, `' OR '`, `DROP TABLE`, `SLEEP(n)` ;
- *path_traversal* : `../`, `..\`, `/etc/passwd`, `/etc/shadow` ;
- *xss* : `<script`, `onerror=`, `javascript:`.

**Liste blanche (F5).** L'IP `10.0.1.5` (scanner interne de l'équipe sécurité)
est retirée de **toutes** les règles avant détection.

### 4.3 Règles de corrélation

| N° | Menace | Condition | Sévérité |
|---|---|---|---|
| **C1** | Compromission probable | `ssh_success` de la même IP qu'une alerte R1, entre le début de la rafale et 10 min après sa fin ; une alerte par couple (R1, compte) | CRITICAL |
| **C2** | Chaîne d'attaque | Alerte R3 de la même IP qu'une alerte R2, commençant entre le début du scan et 30 min après sa fin ; une seule alerte par scan | HIGH |

- **C1** : `first_seen` = celui de R1, `last_seen` = première connexion réussie du
  compte, `event_count` = celui de R1 + 1, `user` = le compte.
- **C2** : `first_seen` = celui de R2, `last_seen` = le plus tardif des alertes R3
  retenues, `event_count` = somme des `event_count` de R2 et de ces R3.

### 4.4 Exemple d'alerte produite

```json
{
  "rule_id": "C1",
  "severity": "CRITICAL",
  "src_ip": "203.0.113.146",
  "first_seen": "2026-10-13T01:14:14Z",
  "last_seen": "2026-10-13T01:21:02Z",
  "event_count": 40,
  "description": "Compromission probable du compte deploy depuis 203.0.113.146",
  "category": null,
  "user": "deploy"
}
```

---

## 5. Analyse de l'incident

À partir des **15 alertes** produites sur les logs fournis.

### 5.1 Chronologie des événements (UTC)

| Début (UTC) | Fin (UTC) | Règle | IP source | Événement |
|---|---|---|---|---|
| 12/10 03:59:59 | 04:04:29 | R1 + R5 | 198.51.100.213 | Force brute SSH (46) — IP déjà connue (`ssh_bruteforce`) — **échoue** |
| 12/10 09:08:57 | 09:09:21 | R1 | 198.51.100.122 | Force brute SSH (9) — échoue |
| 12/10 12:10:05 | 12:10:44 | R1 | 198.51.100.122 | Force brute SSH (14) — échoue |
| 12/10 13:17:08 | 13:18:01 | R2 | 192.0.2.168 | Scan de ports (54 refus) |
| 12/10 13:23:08 | 13:23:37 | R4 | 192.0.2.168 | Scan web — 30 erreurs 404 |
| 12/10 13:30:08 | 13:30:50 | R3 | 192.0.2.168 | Injection SQL (15 requêtes) |
| 12/10 13:33:08 | 13:33:23 | R3 | 192.0.2.168 | Path traversal (4 requêtes) |
| 12/10 13:17:08 | 13:33:23 | **C2** | 192.0.2.168 | **Chaîne d'attaque** scan → web (73) |
| 12/10 21:56:35 | 21:57:14 | R2 | 198.51.100.128 | Scan de ports (40 refus) |
| 13/10 01:14:14 | 01:16:46 | R1 | 203.0.113.146 | Force brute SSH (39) |
| 13/10 01:14:14 | **01:21:02** | **C1** | 203.0.113.146 | **Compromission du compte `deploy`** (CRITICAL) |
| 13/10 09:19:07 | 09:40:07 | R3 | 198.51.100.112 | Sondes XSS (4) |
| 13/10 09:59:07 | 09:59:07 | R3 | 198.51.100.112 | Path traversal (1) |
| 13/10 16:07:20 | 16:22:20 | R5 | 192.0.2.216 | IP malveillante (`scanner`) |

### 5.2 Attaquants identifiés et techniques

- **203.0.113.146 — l'attaque réussie et la plus grave.** Force brute SSH (39
  tentatives en ~2,5 min) **suivie d'une connexion réussie au compte `deploy`**
  à 01:21:02. La corrélation C1 établit une **compromission probable**.
- **192.0.2.168 — chaîne d'attaque web méthodique.** Reconnaissance par scan de
  ports, puis énumération web (30 erreurs 404), puis exploitation (injection SQL
  et path traversal). La corrélation C2 relie le scan et les attaques web.
- **198.51.100.213** : force brute SSH massive (46), IP déjà répertoriée comme
  malveillante — échec.
- **198.51.100.122** : deux salves de force brute distinctes (échec).
- **198.51.100.128** : scan de ports.
- **198.51.100.112** : sondes XSS et path traversal.
- **192.0.2.216** : scanner connu (réputation).

### 5.3 Comptes et serveurs potentiellement compromis

- **Compte `deploy`** sur `srv-web01` : **compromis** (connexion réussie après
  force brute). Il s'agit du point d'entrée confirmé.
- **Serveur `srv-web01`** : exposé à la fois à la compromission SSH et aux
  tentatives d'exploitation web (SQLi, path traversal). À considérer comme
  **potentiellement compromis** tant qu'une investigation n'a pas confirmé
  l'absence d'exécution de code.

### 5.4 Mesures de remédiation recommandées

1. **Isoler et réinitialiser le compte `deploy`** : révoquer ses sessions et clés
   SSH, changer son mot de passe, auditer toutes ses actions après 01:21:02
   (y compris les commandes `sudo`).
2. **Bloquer les IP attaquantes** au pare-feu (203.0.113.146, 192.0.2.168, etc.).
3. **Durcir SSH** : désactiver l'authentification par mot de passe (clés
   uniquement), déployer `fail2ban`, limiter les tentatives.
4. **Corriger l'application web** : requêtes paramétrées contre les injections
   SQL, validation stricte des chemins contre le path traversal ; vérifier dans
   les logs applicatifs si une exploitation a réussi.
5. **Faire tourner les secrets** accessibles au compte `deploy`.
6. **Surveillance renforcée** : conserver les alertes C1/C2 comme incidents
   prioritaires.

---

## 6. Évaluation critique

### 6.1 Faux positifs identifiés

- **Redondance R1/R5** sur `198.51.100.213` : la même attaque génère une alerte de
  force brute et une alerte de réputation. Ce n'est pas un faux positif au sens
  strict (les deux informations sont justes et complémentaires), mais cela peut
  surcharger l'analyste. Une consolidation par IP pourrait être envisagée.
- **R4 (scan web 404)** est sensible aux robots d'indexation légitimes ou aux
  liens morts d'un site : un pic de 404 bénin pourrait déclencher une alerte.
- **R5 (réputation)** dépend de la fraîcheur de la liste : une IP réaffectée
  depuis sa dernière observation malveillante produirait un faux positif.

### 6.2 Faux négatifs identifiés

- **Force brute lente** (« low and slow ») : moins de 5 tentatives par minute
  passe sous le seuil R1.
- **Attaque distribuée** : une force brute répartie sur plusieurs IP n'est vue
  par aucune règle (chaque IP reste sous le seuil).
- **Compromission via IP en liste blanche** : la liste blanche crée un angle mort
  assumé (F5).
- **Charges encodées plus de deux fois** ou obfusquées autrement que par
  pourcentage : hors de portée du double `unquote_plus`.

### 6.3 Effet d'une modification des seuils

Analyse automatisée (`scripts/analyse_seuils.py`) sur les logs fournis :

| Règle | Paramètre | Valeur basse | **Défaut** | Valeur haute |
|---|---|---|---|---|
| **R1** | `threshold` | 3 → **6** alertes | **5 → 4 alertes** | 8 → **4** alertes |
| **R2** | `distinct_ports` | 10 → **2** | **15 → 2** | 20 → **2** |
| **R4** | `threshold` | 10 → **2** | **20 → 1** | 30 → **1** |

Lecture :
- **R1** : abaisser le seuil à 3 ajoute 2 alertes (probables faux positifs liés à
  des échecs légitimes répétés) ; le relever à 8 ne perd aucune des 4 vraies
  attaques, car celles-ci comptent de 9 à 46 tentatives. Le seuil de 5 est un bon
  compromis.
- **R2** : parfaitement **stable** (2 alertes de 10 à 20). Les deux scans réels
  balaient 40 et 54 ports : la règle est robuste au choix du seuil.
- **R4** : abaisser à 10 fait apparaître un second pic de 404 (trafic
  vraisemblablement bénin) ; le seuil de 20 isole le seul scan réellement
  agressif.

### 6.4 Attaques que le système ne peut pas voir

- **Mouvement latéral** après compromission (le SIEM ne corrèle pas les actions
  post-connexion au-delà de C1).
- **Exfiltration de données** (pas de source réseau fine, pas de DLP).
- **Attaques applicatives hors signatures** (logique métier, SSRF, désérialisation).
- **Altération des logs** par un attaquant ayant obtenu les privilèges.
- **Sources non collectées** (DNS, antivirus, authentification applicative).

**Pistes d'amélioration** : seuils adaptatifs, corrélation multi-IP, agrégation
par ASN, enrichissement threat intel en temps réel, détection d'anomalies
statistiques, collecte de sources supplémentaires.

---

## 7. Sécurité du SIEM lui-même

Un SIEM ingère par nature des données hostiles : il doit se protéger des charges
contenues dans les logs.

### 7.1 Injections SQL (NF3)

**Toutes** les requêtes SQLite utilisent des paramètres `?` ; aucune valeur
externe n'est concaténée dans une requête. Les filtres de consultation
(`source`, `event_type`, `src_ip`, `severity`, `rule_id`) sont transmis comme
paramètres liés. Un test dédié injecte `1.1.1.1'; DROP TABLE events; --` dans un
filtre : la table reste intacte et la valeur est traitée comme une simple donnée.

### 7.2 XSS issu des logs (NF4)

Les logs contiennent des charges comme `<script>alert('xss')</script>` (sondes de
l'attaquant 198.51.100.112). Le tableau de bord s'appuie sur l'**échappement
automatique de Jinja2** et n'utilise **jamais** le filtre `safe` sur ces données.
Un test vérifie qu'une charge XSS ressort échappée (`&lt;script&gt;`) et non sous
forme de balise exécutable.

### 7.3 Exposition (NF5)

Le serveur Flask écoute uniquement sur `127.0.0.1` (pas d'exposition réseau) avec
le **mode debug désactivé** (pas de console interactive Werkzeug exploitable).
L'URL des logs est décodée uniquement pour la **comparaison** aux signatures,
jamais exécutée ni réinjectée dans une requête.

---

## 8. Tests

### 8.1 Stratégie

**50 tests `pytest`** (NF9 en demande 20 au minimum), répartis par couche :

| Fichier | Portée | Nb |
|---|---:|---:|
| `test_parsers.py` | Analyseurs, volumes exacts, fuseaux horaires, cas limites | 11 |
| `test_storage.py` | Idempotence, filtres, injection SQL, aller-retour objet/base | 7 |
| `test_rules.py` | Rafales (bornes, 500→1, nouvelle attaque), R1-R5, faux positifs R3, double encodage | 19 |
| `test_correlation.py` | C1, C2, liste blanche, format d'export | 9 |
| `test_dashboard.py` | Routes, filtres, erreur 400, échappement XSS | 9 |

### 8.2 Cas limites couverts

- Rafale de 500 événements → **1 seule** alerte ; bornes de fenêtre **incluses**
  (60 s pile déclenche) ; deux salves séparées → **deux** alertes.
- R2 compte les **ports distincts** (30 refus sur un même port ne déclenchent
  pas).
- R3 **ne déclenche pas** sur des mots légitimes (`/union-jack`, `/scripts/app.js`)
  mais détecte une charge **double-encodée** (`%253Cscript%253E`).
- Idempotence : réingérer les 5 196 événements deux fois n'ajoute **aucun**
  doublon.
- Sécurité : injection SQL neutralisée, charge XSS échappée, sévérité inconnue →
  400.

### 8.3 Limites de la couverture

- Pas de test **end-to-end** automatisé de l'enchaînement complet
  `ingest → detect → report` en ligne de commande (validé manuellement).
- La performance (NF6) est vérifiée manuellement (`run` en ~1 s, bien en deçà des
  30 s) mais non figée dans un test.
- Les signatures R3 ne sont pas testées de façon exhaustive (fuzzing).

---

## 9. Conclusion

### 9.1 Bilan technique

Le mini-SIEM remplit l'ensemble des exigences fonctionnelles (F1 à F10) et non
fonctionnelles (NF1 à NF10). Il reconstitue fidèlement l'incident : une
**compromission du compte `deploy`** par force brute SSH depuis `203.0.113.146`,
et une **chaîne d'attaque web** (scan → SQLi → path traversal) depuis
`192.0.2.168`. Les volumes normalisés correspondent exactement aux références, la
détection s'appuie sur une fenêtre glissante correcte, et l'application web est
protégée contre les injections SQL et le XSS.

### 9.2 Bilan d'équipe

Projet mené en autonomie. Le découpage en quatre lots et les commits Git
réguliers ont permis de valider chaque étape (volumes, idempotence, détection,
tableau de bord) avant de passer à la suivante.

### 9.3 Pistes d'évolution

- Corrélation multi-IP et détection d'attaques distribuées.
- Seuils adaptatifs et détection d'anomalies statistiques.
- Enrichissement threat intel dynamique et consolidation des alertes par IP.
- Collecte de sources supplémentaires (DNS, logs applicatifs, authentification).

---

## Annexe : usage d'outils d'IA

| Aspect | Détail |
|---|---|
| **Outil utilisé** | Assistant de code IA (Claude). |
| **Fins** | Mise en place de l'architecture modulaire, rédaction des analyseurs et des règles, génération des tests, rédaction de ce rapport. |
| **Vérifications effectuées** | Les volumes de normalisation ont été **comparés aux valeurs de référence** fournies (190 / 3 060 / 1 946) et confirmés. La logique de la fenêtre glissante et des corrélations a été **validée par des tests dédiés** sur des cas limites. Les résultats de l'analyse de sensibilité des seuils ont été **reproduits** par le script `scripts/analyse_seuils.py`. L'incident reconstitué a été relu et jugé cohérent avec les traces. |
| **Corrections apportées** | [À compléter : indiquez ici les ajustements que vous avez faits vous-même — relecture du code, personnalisation des seuils, vérification manuelle d'alertes, etc.] |
```
