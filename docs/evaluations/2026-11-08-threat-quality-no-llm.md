Qualité des menaces et des attack paths (sans LLM)

Évaluation du 8 novembre 2026 sur main (fc0a937, après #65 et #66), comparée à bfe5f01 (juste avant #65). Méthode : --no-ai --attack-flow --output-format json sur les 17 templates de threatModel_Template/ (6 d'entre eux aussi sur bfe5f01). Aucun LLM : on mesure donc le moteur de règles, le mapping MITRE, le scoring et les deux générateurs d'attack paths.

## 1. Les menaces

### Ce qui a changé avec #65 et #66 (sans LLM)

La liste des menaces est identique avant et après : même nombre, mêmes descriptions, même répartition STRIDE sur les 6 modèles comparés. Le grounding, le filtre ATT&CK par STRIDE et le retrait des identifiants inventés de #65 ne touchent que les menaces produites par l'IA. #66 (casse des protocoles) ne change que le boost des techniques GDAF, et la technique principale de chaque hop reste la même sur les 6 modèles.

Ce qui a vraiment changé, c'est la sévérité, et c'est un net progrès :

| 6 modèles, 443 menaces | Avant #65 | Après #65 |
|---|---|---|
| CRITICAL | 237 (53 %) | 52 (12 %) |
| Niveaux utilisés | 3 (CRITICAL, HIGH, MEDIUM) | 5 (CRITICAL à INFORMATIONAL) |
| Scores distincts (Advanced Cloud) | 16 | 31 |
| Médiane | 9,0 | 7,1 |

Avant, plus de la moitié des menaces étaient critiques, donc le tri ne servait à rien. Maintenant le haut du classement a du sens (injection SQL sur la base produit, élévation de privilèges sur Auth Service, évasion de conteneur) et les menaces génériques d'acteurs ou de journalisation tombent en LOW.

Petit défaut introduit par #65 : le JSON contient des scores bruts non arrondis (7.699999999999999, 7.1000000000000005).

### Répartition : toujours déséquilibrée

Sur les 17 templates (1 257 menaces) :

| STRIDE | Menaces | Part |
|---|---|---|
| Information Disclosure | 351 | 28 % |
| Spoofing | 317 | 25 % |
| Elevation of Privilege | 207 | 16 % |
| Repudiation | 199 | 16 % |
| Tampering | 165 | 13 % |
| Denial of Service | 18 | 1,4 % |

Le déni de service est presque absent : seulement 4 règles DoS sur 57, et la plus large (is_public: True) ne se déclenche jamais.

### Pertinence : surtout du générique

- 92 % des menaces viennent de 10 règles génériques qui produisent la même phrase pour chaque composant : les 4 règles « tout serveur » (patchs, durcissement, élévation de privilèges, journalisation : 144 chacune), les 3 règles « tout acteur », et 3 règles de flux (interception, usurpation, franchissement de frontière). Seulement ~95 menaces sur 1 257 sont spécifiques au type de composant.
- 28 règles sur 57 ne se déclenchent sur aucun template. Une partie vient des modèles (pas de FTP, pas de switch), mais plusieurs sont des bugs du moteur de règles (custom_threats.py) :
  - sink.type, source.type, data.type ne se résolvent jamais : le type DSL est dans le dict servers, pas sur l'objet pytm. Exemple : la règle « flux non authentifié vers une base de données » (EoP critique) devrait se déclencher sur au moins 15 flux dans 10 templates, et ne se déclenche jamais.
  - source.boundary.isTrusted : l'attribut pytm s'appelle inBoundary.
  - contains_sensitive_data attend une liste, alors que data est un DataSet : la condition est toujours fausse.
  - Les types sont comparés tels quels : type="api_gateway" (5 serveurs) et type="load_balancer" (4) ne matchent pas les règles api-gateway et load-balancer. Pourtant validate traite déjà _ et - comme équivalents.
  - Kerberoasting a stride_category: "Credential Access", qui n'est pas une catégorie STRIDE : la règle se déclenche sur les deux contrôleurs de domaine d'On-Prem (201 menaces générées), mais les deux menaces disparaissent du rapport (199).
- Faux positifs de chiffrement : 72 flux en HTTPS, TLS, SSH ou mTLS n'ont pas is_encrypted=True et reçoivent « Data interception on an unencrypted channel ». Cela représente environ 40 % des 177 menaces d'interception. Le protocole devrait suffire à déduire le chiffrement.
- Mapping ATT&CK souvent faux. Les règles n'ont pas d'ID de technique (12 sur 57 ont des capec_ids). Le mapping passe donc par des mots communs avec CAPEC, puis par la table CAPEC vers ATT&CK, très incomplète (185 entrées). Exemples sur Advanced Cloud :
  - injection SQL → T1195 Supply Chain Compromise + T1036 Masquerading (attendu : T1190)
  - session hijacking → T1547 Boot or Logon Autostart (attendu : T1539 / T1550)
  - interception de données → T1005, T1115 Clipboard Data, T1012 Query Registry (attendu : T1040 / T1557)
  - patchs manquants → T1195 (attendu : T1190 / T1068 / T1210)
  - authentification faible sur l'API Gateway → T1574 Hijack Execution Flow
- Petits défauts de texte : « API Gateway API Gateway » (nom répété), « serverless function API Gateway ».

Conclusion menaces : sans LLM, la sévérité est désormais crédible, mais la liste reste une check-list générique, avec des règles spécifiques en partie inactives à cause de bugs, et des techniques ATT&CK souvent hors sujet. C'est le LLM qui apporte aujourd'hui la spécificité.

## 2. Les attack paths au format Attack Flow

Il y a deux générateurs.

### a) AttackFlowGenerator (STRIDE, afb/optimized_path_<catégorie>.afb, et section « attack paths » du rapport HTML)

Il est à reprendre. Sur tous les modèles testés, avant comme après #65 :

- Le même chemin est produit pour chaque catégorie STRIDE. Les fichiers « Tampering », « Information Disclosure » et « Denial of Service » d'un même modèle ont la même description, mot pour mot.
- Ce chemin ignore la topologie : il saute Product Database → Auth Service → Product Database sans flux entre eux, et pose « Exfiltration Over Physical Medium » sur un flux réseau.
- Il commence toujours par Supply Chain Compromise et finit toujours par « Impact: Denial of Service », quelle que soit la catégorie.
- La cause : un DFS qui s'arrête aux 100 premiers chemins (tous ont le même préfixe), puis un choix du chemin « maximum de la somme des scores », ce qui favorise le plus long. La déduplication des narratifs ajoutée par #65 masque le symptôme.
- Ces chemins alimentent le narratif IA (attack_path_narrative) : le LLM reçoit donc un chemin incohérent.

### b) GDAF (gdaf/<objectif>/<acteur>_<id>.afb) : nettement meilleur

Il est piloté par objectifs et acteurs (context YAML), il suit les dataflows et propose de vraies techniques par hop, avec des branches OR (DCSync et Golden Ticket sur le contrôleur de domaine, Phishing vers LSASS sur le poste). Sur les 17 templates : 286 scénarios, de 1 à 8 hops.

Ses limites :

- Les niveaux de risque sont saturés : IoT 28/28 CRITICAL, UAV 24/24, On-Prem 42/43, Satellite 90/91 HIGH. Ils ne départagent rien.
- Peu de diversité : 40 techniques distinctes en tout. T1078 et T1190 représentent 327 hops sur environ 840. Simple Monolithic n'a que 2 techniques, IoT 3 (T1190 jusque sur l'IoT Hub interne), et LSASS Memory apparaît sur l'ERP.
- Beaucoup de doublons : Satellite donne 91 scénarios pour 21 chemins distincts, IoT 28 pour 9.
- 21 % de scénarios à 1 hop (« Valid Accounts sur la cible »), ce qui ne constitue pas vraiment un chemin.
- entry_preference: internal et supply-chain sont traités comme externes. Traditional Enterprise Network donne 0 scénario : aucun flux ne relie la DMZ au réseau interne, et l'acteur internal ne part pas de l'intérieur.
- Les fichiers .afb ne font pas de lien vers les IDs des menaces STRIDE, ni vers les mitigations ou les détections, et n'ont pas de nœuds condition (les prérequis comme « credentials obtenus »).
- Il ne tourne que si le modèle a un context YAML. Sinon, il s'appuie sur _auto_context, qui n'a pas été évalué ici.

## 3. Améliorations proposées (une PR chacune, par ordre d'impact)

1. Réparer le moteur de règles : résoudre source/sink.type depuis le dict des serveurs, inBoundary, DataSet, la normalisation _/-, et la catégorie du Kerberoasting. Ajouter un test de régression par règle, plus un test « chaque règle se déclenche sur au moins une fixture ». Effet attendu : environ +20 menaces spécifiques réactivées sur les templates.
2. Déduire is_encrypted du protocole (registre des protocoles) quand il n'est pas déclaré. Effet : environ −70 faux positifs.
3. Donner des IDs ATT&CK explicites à chaque règle (attack_ids), utilisés en priorité sur la correspondance de mots CAPEC.
4. Remplacer les chemins STRIDE par les scénarios GDAF dans le rapport HTML et pour le narratif IA. À défaut, contraindre AttackFlowGenerator à la topologie et exiger que le dernier hop soit de la catégorie visée.
5. GDAF : calibrer le niveau de risque en relatif (rang ou percentiles par modèle), diversifier les techniques selon la position du hop (accès initial, mouvement latéral, tactique finale), dédupliquer les scénarios, gérer internal et supply-chain, et relier chaque hop aux menaces STRIDE et à leurs mitigations dans le .afb.
6. Ajouter des règles DoS et Repudiation spécifiques (rate limiting, épuisement de ressources par type, logs non signés). Fusionner les 4 règles génériques serveur en une seule menace « hygiène » par composant, pour que le rapport ne soit plus noyé.
7. Arrondir les scores dans le JSON.

Les commandes et le script d'analyse peuvent être relancés : --no-ai --attack-flow --output-format json, puis comptage par règle (regex sur THREAT_RULES).
