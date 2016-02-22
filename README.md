# Infiniband_Agent
Client/Serveur communicant avec les éléments de protection de PIGA

Basé sur les sources de IBPing, ce projet permet la communication entre deux machines distantes en utilisant les technologies Infiniband.
Actuellement, il implémente RDMA (remote Direct Memory Access) over Infiniband.
Comme pour IBPing, l'échange des paramètres IB se fait sur une connexion TCP classique puis la connexion IB prend le relais.
Ensuite, les deux agents communiquent avec les éléments de protection de PIGA.
D'un côté, le client écoute et écrit sur les procfs de PIGA-Kernel, de l'autre, le serveur communique avec le moniteur de référence PIGA.
Toute l'architecture est multi-threadé pour ne pas ralentir le système contrôlé lorsque le dispositif est en mode audit.
Il y a des verrous de sécurité pour, au choix, soit bloqué la machine, soit ne pas la bloquer si la connexion IB tombe.
De plus, une connexion TCP de secours sera mise en place en cas de défaut de la connexion IB.

Ce projet a été créé pour cette thèse : http://www.theses.fr/2014ORLE2017 (chapitre 3 et 4)
