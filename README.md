##Popis aplikace
Aplikace načte a zpracuje vstupní argumenty a zkontroluje jejich korektnost.<br>
Napojí se na specifikované rozhraní a aplikuje na něj patřičné filtry.<br>
Následně se volá funkce `pcap_loop`, která zachytává filtrované pakety.<br>
Nad každým paketem zavolá tzv. `pcap_handler` fuknci.<br>
To je funkce, která obstarává samotné zpracování paketu. V mojí implementaci se funkce jmenuje `callback`. <br>
Funkce `callback` využívá řadu podpůrných funkcí pro zpracování konkrétních typů paketů a výsledkem je výpis<br>
dat z paketu v požadovaném formátu na výstup programu.

##Možné parametry:
* -i nazev_rozhrani (Rozhraní, na kterém se bude poslouchat.<br>
    Nebude-li tento parametr uveden, vypíše se seznam aktivních rozhraní.)
* -p int:cislo_portu (Sniffer bude zachytávat pakety pouze na daném portu,<br>
        nebude-li tento parametr uveden, uvažují se všechny porty.)
* -t | --tcp (Bude zobrazovat pouze tcp pakety.)
* -u | --udp (Bude zobrazovat pouze udp pakety.)
<br><br>
Pokud nebude specifikován typ paketu, uvažují se tcp i udp pakety zároveň.<br>
Pokud bude specifikován více jak jeden typ, uvažuje se jejich kombinace.<br><br>
* -n | --num int:pocet_paketu (Určuje počet vypsaných paketů,
    pokud nebude počet specifikován, vypíše se pouze 1 paket.)
* -a | --arp (Filtruje pouze ARP pakety a žádné jiné.)
* -6 | --ip6 (Filtruje IPv6 protokol, lze kombinovat s IPv4, tcp, udp a port filtrováním.)
* -4 | --ip4 (Filtruje IPv6 protokol, lze kombinovat s IPv6, tcp, udp a port filtrováním.)
* -A | --all (Nefiltruje se nic, zachytávají se všechny pakety, vypisují se pouze podporované.)
* -s | --stats (Výpis statistik o síťovém provozu na konci běhu programu.)<br><br>
Krátké parametry je možné zadávat ve tvaru "-n5" anebo "-n 5".<br>
Dlouhé parametry je nutné zadávat ve tvaru "--num=5".

##Příklady spuštění
Je nutné vždy spouštět s _root_ právy. Například s uvozujícím `sudo` příkazem.<br>
###Základní specifikace
* `sudo ./ipk-sniffer` - vypíše dostupná rozhraní
* `sudo ./ipk-sniffer -i enp24s0` - vypíše jeden TCP nebo UDP paket, IPv4 nebo IPv6 adresy, libovolný port 
* `sudo ./ipk-sniffer -i enp24s0 --tcp -p 443 -n 500` - vypíše 500 TCP paketů na portu 443, IPv4 nebo IPv6 adresy
###Rozšíření
* `sudo ./ipk-sniffer -i enp24s0 -4 -t -p 80` - vypíše jeden TCP paket IPv4 adresy
* `sudo ./ipk-sniffer -i enp24s0 -a -p 80 -n 50` -  vypíše 50 ARP paketů IPv4 adresy, port je ignorován
* `sudo ./ipk-sniffer -i enp24s0 -a -p 42 -n 20 -A -s` - vypíše 20 jakýchkoli paketů a statistiky
## Seznam odevzdaných souborů
ipk-sniffer.cpp, ipk-sniffer.h, Makefile, my_dns_cache.cpp, my_dns_cache.h, my_arp.h, my_getnameinfo.cpp,<br>
my_getnameinfo.h, my_string.cpp, my_string.h, README.md