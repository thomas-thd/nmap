# Nmap Inspect — Projet minimal

## Description
**Nmap Inspect** est un script Python qui lit des fichiers XML générés par **Nmap** et produit un rapport clair pour chaque appareil détecté sur un réseau.  
Le script affiche uniquement les hôtes actifs avec ports ouverts ou OS détecté, et fournit pour chacun :  

- IP et hostname (si disponible)  
- OS détecté (si disponible)  
- Ports ouverts et services correspondants  
- Estimation simple du type d’équipement (serveur, poste utilisateur, box, etc.)  

Le script est **simple, rapide et idéal pour des audits réseau pédagogiques ou analyses rapides**.

---

## Contenu du dépôt
- `nmap_inspect.py` — script principal qui parse les fichiers Nmap XML dans `scans/` et affiche un rapport par appareil.  
- `scans/` — dossier attendu contenant les fichiers `.xml` (export Nmap `-oX`).  

---

## Usage

1. Place tes fichiers Nmap XML dans le dossier `scans/` (ex. `scans/scan_192.168.0.0-24.xml`).  
2. Lancer le script (affichage console) :
```bash
python nmap_inspect.py
