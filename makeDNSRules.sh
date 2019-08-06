#!/bin/bash
# syntax: ./makeDNSRules.sh domainlist.txt
#
# Copy domain list to array var
# Cut array into separate names by periods
# Count letters in names and insert |00| values before each word
# Loop through each and output to screen the corresponding snort rule 
# Derek Petersen    8/6/2019

file=$1
#echo $file
#SNORT Rule SID counter
c=1

for dname in $(cat $file); 
  do 
    #add periods to beginning of all domain names that dont have them and store it as curname
    if ! [[ $dname =~ ^\..* ]];
	then
	  #echo ".$dname"
	  curname=".$dname"
        else 
	  #echo $dname
	  curname=$dname
    fi

	# read in each domain name (curname) and count chars, 
	# insert hex blocks (|00|) and print snortrule
	while IFS='.' read -ra ADDR;
	do 
	  finalname=""
	  for i in "${ADDR[@]}";
	  do
	    dnschar=$(printf "%02d" $(echo -n $i | wc -c))
	    finalname+=$(echo -e "|$dnschar|$i")
	  done
	done <<< $curname
	cleanname=$(echo "$finalname|00|" | cut -c 5-)
	echo "alert udp any any <> any any (msg:\"APT1 DNS $cleanname\"; content: \"$cleanname\"; sid:500000$c;)"
	let "c++"
done