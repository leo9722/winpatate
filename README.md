# winpatate


Wincheck.sh est un script bash qui rassemble l'execution de plusieurs commandes d'ennumération au sein d'un actiove directory

## Installation

```bash
git clone  https://github.com/leo9722/winpatate.git
cd winpatate 
chmod +x wincheck.sh && chmod +x install.sh 
./install.sh
./install wincheck.sh
```

## Utilisation

Il suffit juste de fournir l'ip de la taget et le script se chargera de recupérer le domaine associé et ainsi d'y effectuer diverses attaques.

Parmis celles-ci :

- full nmap (-sS -sU -p- )
- anonymous bind ldap search 
- enum4linux ( get potential users)
- ASP_REQ_ROAST attack ( si users trouvé)
- Password Spraying ( si users trouvé )
- Kerberoasting ( si user trouvé )
- crack de mdp ( si creds trouvé )
- check vuln adcs
- petitpotam module 
