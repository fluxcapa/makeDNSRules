# makeDNSRules
Given a list of domain names, this BASH script will return Snort Rules looking for those domains in DNS queries.

syntax:
```
./makeDNSRules.sh list.txt
```

example list.txt:
```
GT446.ezua.COM
aunewsonline.com
avvmail.com
cas.ibooks.tk
cas.m-e.org.ru
```

example output:
```
alert udp any any <> any any (msg:"APT1 DNS |05|GT446|04|ezua|03|COM|00|"; content: "|05|GT446|04|ezua|03|COM|00|"; sid:5000001;)
alert udp any any <> any any (msg:"APT1 DNS |12|aunewsonline|03|com|00|"; content: "|12|aunewsonline|03|com|00|"; sid:5000002;)
alert udp any any <> any any (msg:"APT1 DNS |07|avvmail|03|com|00|"; content: "|07|avvmail|03|com|00|"; sid:5000003;)
alert udp any any <> any any (msg:"APT1 DNS |03|cas|06|ibooks|02|tk|00|"; content: "|03|cas|06|ibooks|02|tk|00|"; sid:5000004;)
alert udp any any <> any any (msg:"APT1 DNS |03|cas|03|m-e|03|org|02|ru|00|"; content: "|03|cas|03|m-e|03|org|02|ru|00|"; sid:5000005;)
```
