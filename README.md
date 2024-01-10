# Sviluppo di un software per la rilevazione di host e dispositivi di rete basato sui protocolli UDP e LLDP e di un software per attacchi di tipo "ARP cache poisoning"

Autore: **Alessandro Pistola**

Il progetto risulta essere diviso principalmente in due aree. La prima riguarda la parte progettuale comprendente gli strumenti di rilevazione degli host e dei dispositivi in una rete, mentre, la seconda parte fa riferimento ad una specifica tipologia di attacco, il cosiddetto avvelenamento della cache ARP.
Nello sviluppo dello script riguardante l'attacco di tipo ARP cache poisoning ci si avvale della libreria Scapy essendo il focus dello script nell'attacco piuttosto che nella sua implementazione, mentre, per lo sviluppo dello script per la rilevazione di host e dispositivi di rete si e voluto mantenere il focus nell'implementazione e proprio per questo non viene utilizzata nessuna libreria ed ogni livello (di interesse) viene quindi destrutturato per ottenere le informazioni ricercate.

**Per maggiori informazioni consultare la [relazione](https://github.com/alepistola/LLDP-UDP-net-scan/blob/main/relazione.pdf)**
