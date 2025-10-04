# Nmap Inspect — Projet minimal

Description
Nmap Inspect est un script Python qui lit des fichiers XML generes par Nmap et produit un rapport clair pour chaque appareil detecte sur un reseau.
Le script affiche uniquement les hotes actifs avec ports ouverts ou OS detecte, et fournit pour chacun :

- IP et hostname (si disponible)
- OS detecte (si disponible)
- Ports ouverts et services correspondants
- Estimation simple du type d'equipement (serveur, poste utilisateur, box, etc.)

Le script est simple, rapide et ideal pour des audits reseau pedagogiques ou analyses rapides.

---

Contenu du depot
- nmap_inspect.py — script principal qui parse les fichiers Nmap XML dans scans/ et affiche un rapport par appareil.
- scans/ — dossier attendu contenant les fichiers .xml (export Nmap -oX).

---

Configuration attendue des dossiers (structure)
Place-toi a la racine du depot et assure-toi d'avoir cette arborescence :

/ton-repo/

├─ nmap_inspect.py        # script principal

├─ README.md              # ce fichier

└─ scans/                 # <-- place ici tes fichiers .xml Nmap (obligatoire)
    ├─ scan_192.168.0.0-24.xml
    
    ├─ host1.xml
    
    └─ ...
- scans/ doit exister avant d'executer le script.
- Le script ne cree pas automatiquement scans/ si absent : cree-le manuellement (mkdir scans) et place-y les fichiers XML.

---

Commande Nmap attendue
Pour generer le fichier XML a analyser par le script, utiliser (exemple pour un /24) :

nmap -T4 -A -v -oX scans/scan_192.168.0.0-24.xml 192.168.0.0/24

- -T4 : vitesse elevee
- -A  : detection OS, version et scripts par defaut
- -v  : verbeux
- -oX : export XML dans scans/

> Execute cette commande uniquement sur des reseaux que tu possedes ou pour lesquels tu as l'autorisation.

---

Usage du script

1. Genere et place les fichiers .xml Nmap dans scans/.
2. Lancer le script (affichage console) :

python nmap_inspect.py

3. (Optionnel) Generer un fichier texte par hote :

python nmap_inspect.py --per-host

4. (Optionnel) Generer CSV (si implemente dans le script) :

python nmap_inspect.py --per-host --csv

---

Exemple de sortie
=== Host #1 — 192.168.0.10 ===
IP: 192.168.0.10    Hostname: web01.local
OS detectes: Linux 4.15 - 5.19 (accuracy=98%)
Ports ouverts (2):
  - 22/tcp: ssh  | OpenSSH 7.4
  - 80/tcp: http  | nginx 1.14
Estimation type d'equipement: Serveur (SSH + services web)

---

Remarques importantes
- Place uniquement les fichiers .xml generes par nmap -oX dans scans/.
- Le script ne lance aucun scan ; il lit uniquement les XML fournis.
- Ne scanne que des cibles pour lesquelles tu as l'autorisation.

---

Licence
Ce projet est distribue sous la licence Apache License 2.0.
Voir le fichier LICENSE dans le depot pour le texte complet de la licence.

