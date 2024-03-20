#!/bin/bash
# https://github.com/yaseenabdulsatar/openvpn-install/
# https://github.com/Nyr/openvpn-install


scriptpath=$0
# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
        sudo bash $scriptpath $@
        exit
fi
# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        echo "The system is running an old kernel, which is incompatible with this installer."
        exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
        group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        group_name="nobody"
else
        echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
        exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
        echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
        exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
        echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
        exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
        echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
        exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
        echo '$PATH does not include sbin. Try using "su -" instead of "su".'
        exit
fi


#-------


if [[ "$EUID" -ne 0 ]]; then
        sudo bash $scriptpath %@
        exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
        echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
        exit
fi
tls_option () {
        tlstype=$(cat /etc/openvpn-tls-type)
        case "$tlstype" in
                none)

                ;;
                tls-crypt)
                echo "<tls-crypt>"
                sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
                echo "</tls-crypt>"
                ;;
                tls-crypt-v2)
                openvpn --genkey tls-crypt-v2-client /etc/openvpn/server/1.key --tls-crypt-v2 /etc/openvpn/server/tc.key
                echo "<tls-crypt-v2>"
                cat "/etc/openvpn/server/1.key"
                echo "</tls-crypt-v2>"
                rm /etc/openvpn/server/1.key
                ;;
                tls-auth)
                echo "key-direction 1"
                echo "<tls-auth>"
                sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
                echo "</tls-auth>"
                ;;
        esac
}
new_client () {
        # Generates the custom client.ovpn
        {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        tls_option
        } > ~/"$client".ovpn
        echo "" > /etc/openvpn/client/"$client"
}


#-------


tls_option1 () {
        if [[ -e /etc/openvpn/server/client-common1.txt ]]; then
                tls2type=$(cat /etc/openvpn-tls2-type)
                case "$tls2type" in
                        none)

                        ;;
                        tls-crypt)
                        echo "<tls-crypt>"
                        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/othertc.key
                        echo "</tls-crypt>"
                        ;;
                        tls-crypt-v2)
                        openvpn --genkey tls-crypt-v2-client /etc/openvpn/server/1.key --tls-crypt-v2 /etc/openvpn/server/othertc.key
                        echo "<tls-crypt-v2>"
                        cat "/etc/openvpn/server/1.key"
                        echo "</tls-crypt-v2>"
                        rm /etc/openvpn/server/1.key
                        ;;
                        tls-auth)
                        echo "key-direction 1"
                        echo "<tls-auth>"
                        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/othertc.key
                        echo "</tls-auth>"
                        ;;
                esac
        fi
}
new_client1 () {
        # Generates the custom client-other.ovpn
        if [[ -e /etc/openvpn/server/client-common1.txt ]]; then
                {
                cat /etc/openvpn/server/client-common1.txt
                echo "<ca>"
                cat /etc/openvpn/server/easy-rsa/pki/ca.crt
                echo "</ca>"
                echo "<cert>"
                sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client"-other.crt
                echo "</cert>"
                echo "<key>"
                cat /etc/openvpn/server/easy-rsa/pki/private/"$client"-other.key
                echo "</key>"
                tls_option1
                } > ~/"$client"-other.ovpn
                echo "" > /etc/openvpn/client/"$client"-other
        fi
}

#--------

default=$(echo `echo $@` | grep -o "\-\-default" | cut -c -9)
iphostarg=$(echo `echo $@` | grep -o "\-\-ip-host=[a-zA-Z0-9./?=_-]*" | cut -c 11-)
public_ip=$(echo $iphostarg)
if [[ "$iphostarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                public_ip=$iphostarg
        fi
fi
protocolarg=$(echo `echo $@` | grep -o "\-\-protocol=.*" | cut -c 12-15)
protocol=$(echo $protocolarg)
if [[ "$protocolarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                protocol=udp
        fi
fi
portarg=$(echo `echo $@` | grep -o "\-\-port=[a-zA-Z0-9./?=_-]*" | cut -c 8-)
port=$(echo $portarg)
if [[ "$portarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                port="1194"
        fi
fi
vpntypearg=$(echo `echo $@` | grep -o "\-\-vpntype=.*" | cut -c 11-12)
addvpnoption=$(echo $vpntypearg)
if [[ "$vpntypearg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                addvpnoption="1"
        fi
fi
topologyarg=$(echo `echo $@` | grep -o "\-\-topology=.*" | cut -c 12-13)
topology=$(echo $topologyarg)
if [[ "$topologyarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                topology=1
        fi
fi
otherportarg=$(echo `echo $@` | grep -o "\-\-otherport=[a-zA-Z0-9./?=_-]*" | cut -c 13-)
portl=$(echo $otherportarg)
if [[ "$otherportarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                portl="`echo $(($port+1))`"
        fi
fi
otherprotocolarg=$(echo `echo $@` | grep -o "\-\-otherprotocol=.*" | cut -c 17-20)
protocoll=$(echo $otherprotocolarg)
if [[ "$otherprotocolarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                protocoll=1
        fi
fi
othertopologyarg=$(echo `echo $@` | grep -o "\-\-othertopology=.*" | cut -c 17-18)
topologyl=$(echo $othertopologyarg)
if [[ "$othertopologyarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                topologyl=1
        fi
fi
extraarg=$(echo `echo $@` | grep -o "\-\-extraoptions=.*" | cut -c 16-17)
adv=$(echo $extraarg)
if [[ "$extraarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                adv=1
        fi
fi
dnsarg=$(echo `echo $@` | grep -o "\-\-dns=.*" | cut -c 7-8)
dns=$(echo $dnsarg)
if [[ "$dnsarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                dns=1
        fi
fi
tlsarg=$(echo `echo $@` | grep -o "\-\-tls=.*" | cut -c 7-8)
tls=$(echo $tlsarg)
if [[ "$tlsarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                tls=1
        fi
fi
othertlsarg=$(echo `echo $@` | grep -o "\-\-othertls=.*" | cut -c 12-13)
othertls=$(echo $othertlsarg)
if [[ "$othertlsarg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                othertls=1
        fi
fi
clientnamearg=$(echo `echo $@` | grep -o "\-\-clientname=[a-zA-Z0-9./?=_-]*" | cut -c 14-)
unsanitized_client=$(echo $clientnamearg)
if [[ "$clientnamearg" == "" ]]; then
        if [[ "$default" == "--default" ]]; then
                unsanitized_client=client
        fi
fi

#--------


forcearg=$(echo `echo $@` | grep -o "\-\-force" | cut -c -7)
installvpn () {
        # Detect some Debian minimal setups where neither wget nor curl are installed
        clear
        if ! hash openvpn 2>/dev/null; then
                echo "openvpn is required to use this installer."
                apt-get update
                                apt-get install -y openvpn
        fi
                if ! hash ifconfig 2>/dev/null; then
                echo "net-tools is required to use this installer."
                apt-get update
                                apt-get install -y net-tools
        fi
                if ! hash openssl 2>/dev/null; then
                echo "openssl is required to use this installer."
                apt-get update
                                apt-get install -y openssl
        fi
                if $(dpkg -l | grep ca-certificates) 2>/dev/null; then
                echo "ca-certificates is required to use this installer."
                apt-get update
                                apt-get install -y ca-certificates
        fi
        if ! hash wget 2>/dev/null; then
                echo "Wget is required to use this installer."
                apt-get update
                apt-get install -y wget
        fi
        echo 'Welcome to this OpenVPN road warrior installer!, use the installer with the arg "sudo openvpn-install --help" to see the automation options'
        # If system has a single IPv4, it is selected automatically. Else, ask the user
        if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
                number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
                echo
                echo "Which IPv4 address should be used?"
                ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
                read -p "IPv4 address [1]: " ip_number
                until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
                        echo "$ip_number: invalid selection."
                        read -p "IPv4 address [1]: " ip_number
                done
                [[ -z "$ip_number" ]] && ip_number="1"
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
        fi
        # If $ip is a private IP address, the server must be behind NAT
        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                if [[ "$iphostarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
                                [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
                        else
                                echo
                                echo "-----------------------------------------------------------------------------------------------"
                                echo "it is better to have a static public ip, otherwise you will face some problems later, 'you can setup a DNS for your azure vm (in the azure vm see the DNS option)'"
                                echo "-----------------------------------------------------------------------------------------------"
                                echo "This server is behind NAT. What is the public IPv4 address or hostname?"
                                # Get public IP and sanitize with grep
                                get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
                                read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
                                # If the checkip service is unavailable and user didn't provide input, ask again
                        fi
                        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
                                echo "Invalid input."
                                read -p "Public IPv4 address / hostname: " public_ip
                        done
                        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
                fi
        fi
        # If system has a single IPv6, it is selected automatically
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
        fi
        # If system has multiple IPv6, ask the user to select one
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
                number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
                echo
                echo "Which IPv6 address should be used?"
                ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
                read -p "IPv6 address [1]: " ip6_number
                until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
                        echo "$ip6_number: invalid selection."
                        read -p "IPv6 address [1]: " ip6_number
                done
                [[ -z "$ip6_number" ]] && ip6_number="1"
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
        fi
        if [[ "$protocolarg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        protocol=1
                else
                        echo
                        echo "-----------------------------------------------------------------"
                        echo "it's best if you go with the defaults -"
                        echo "-for the protocol and the port (UDP port 1194)"
                        echo "if you go with any other settings you-"
                        echo "-will need to open the selected port in the azure virtual network"
                        echo "-----------------------------------------------------------------"
                        echo "Which protocol should OpenVPN use?"
                        echo "   1) UDP (recommended)"
                        echo "   2) TCP"
                        read -p "protocol [1]: " protocol
                fi
                until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
                        echo "$protocol: invalid selection."
                        read -p "protocol [1]: " protocol
                done
                case "$protocol" in
                        1|"")
                        protocol=udp
                        ;;
                        2)
                        protocol=tcp
                        ;;
                esac
        fi
        if [[ "$portarg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        [[ -z "$port" ]] && port=1194
                else
                        echo
                        echo "What port should OpenVPN listen to?"
                        read -p "port [1194]: " port
                fi
                until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
                        echo "$port: invalid port."
                        read -p "port [1194]: " port
                done
                [[ -z "$port" ]] && port="1194"
        fi
        if [[ "$vpntypearg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        [[ -z "$addvpnoption" ]] && addvpnoption=1
                else
                        echo
                        echo "Do you want this server to be configured to 'change the public ip' or 'connect only'?"
                        echo "the 'change the public ip' configuration changes the public ip of the clients by proxying all the traffic thru the server"
                        echo "while the 'connect only' configuration only allows the clients to see each other worldwide"
                        echo "   1) Change the ip, changes the public ip of the clients and allows them to see each other worldwide "
                        echo "   2) Connect only, allow the clients to see each other worldwide without changing their public ip"
                        echo "   3) Both, create two vpn configurations on this server"
                        if [[ "$addvpnoption" = "" ]]; then
                                read -p "vpn type [1] : " addvpnoption
                        fi
                fi
        until [[ -z "$addvpnoption" || "$addvpnoption" =~ ^[1-3]$ ]]; do
                echo "$addvpnoption: invalid selection ."
                read -p "vpn type [1] : " addvpnoption
        done
        fi
        case "$addvpnoption" in
                1|"")
                addvpn2=0
                vpntype=1
                ;;
                2)
                addvpn2=0
                vpntype=2
                ;;
                3)
                addvpn2=1
                vpntype=1
                ;;
        esac
        if [[ "$extraarg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        adv=2
                else
                        echo
                        echo "whow extra setup options?"
                        echo " 1) no"
                        echo " 2) yes"
                        read -p "extra options [1] : " adv
                fi
        fi
        until [[ -z "$adv" || "$adv" =~ ^[12]$ ]]; do
                echo "$adv: invalid selection."
                read -p "extra options [1] : " adv
        done
                case "$adv" in
                1|"")
                adv=no
                ;;
                2)
                adv=yes
                ;;
        esac
        case "$vpntype" in
                1|"")
                vpntype=redirect-gateway
                ;;
                2)
                vpntype=vpn-gateway
                ;;
        esac
        if [[ "$topologyarg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        topology=1
                else
                        if [[ "$adv" == "yes" ]]; then
                                echo
                                echo "some clients support only 'topology net30' and dosen't support 'topology subnet'"
                                echo "do you want this server to use 'topology net30' or 'topology subnet'?"
                                echo "press enter if you don't know."
                                echo " 1) topology subnet"
                                echo " 2) topology net30"
                                read -p "topology [1] : " topology
                        fi
                fi
        fi
        until [[ -z "$topology" || "$topology" =~ ^[12]$ ]]; do
                echo "$topology: invalid selection."
                read -p "topology [1] : " topology
        done
        case "$topology" in
                1|"")
                topology=subnet
                ;;
                2)
                topology=net30
                ;;
        esac
        if [[ "$addvpn2" = 1 ]]; then
                if [[ "$othertopologyarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                topologyl=1
                        else
                                if [[ "$adv" == "yes" ]]; then
                                        echo
                                        echo "do you want the other configuration to use 'topology net30' or 'topology subnet'?"
                                        echo "press enter if you don't know."
                                        echo " 1) topology subnet"
                                        echo " 2) topology net30"
                                        read -p "topology [1] : " topologyl
                                fi
                        fi
                        until [[ -z "$topologyl" || "$topologyl" =~ ^[12]$ ]]; do
                                echo "$topology: invalid selection ."
                                read -p "other topology [1] : " topologyl
                        done
                fi
                case "$topologyl" in
                        1|"")
                        topologyl=subnet
                        ;;
                        2)
                        topologyl=net30
                        ;;
                esac
        fi
        if [[ "$tlsarg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        tls="1"
                else
                        if [[ "$adv" == "yes" ]]; then
                                echo
                                echo "what tls type do you want the clients to use"
                                echo "   1) tls-crypt-v2 (recommanded)"
                                echo "   2) tls-crypt"
                                echo "   3) tls-auth"
                                echo "   4) none"
                                read -p "tls type [1]: " tls
                        fi
                fi
                until [[ -z "$tls" || "$tls" =~ ^[1-4]$ ]]; do
                        echo "$tls: invalid selection."
                        read -p "tls type [1]: " tls
                done
        fi
        case "$tls" in
                1|"")
                tls=tls-crypt-v2
                ;;
                2)
                tls=tls-crypt
                ;;
                3)
                tls=tls-auth
                ;;
                4)
                tls=none
                ;;
        esac
        if [[ "$addvpn2" = 1 ]]; then
                if [[ "$othertlsarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                othertls="1"
                        else
                                if [[ "$adv" == "yes" ]]; then
                                        echo
                                        echo "what tls type do you want the clients to use (for the second configuration)"
                                        echo "   1) tls-crypt-v2 (recommanded)"
                                        echo "   2) tls-crypt"
                                        echo "   3) tls-auth"
                                        echo "   4) none"
                                        read -p "tls type [1]: " othertls
                                fi
                        fi
                        until [[ -z "$othertls" || "$othertls" =~ ^[1-4]$ ]]; do
                                echo "$othertls: invalid selection."
                                read -p "tls type [1]: " othertls
                        done
                fi
                case "$othertls" in
                        1|"")
                        othertls=tls-crypt-v2
                        ;;
                        2)
                        othertls=tls-crypt
                        ;;
                        3)
                        othertls=tls-auth
                        ;;
                        4)
                        othertls=none
                        ;;
                esac
        fi
        if [[ "$addvpn2" = 1 ]]; then
                if [[ "$otherportarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                portl="`echo $(($port+1))`"
                        else
                                echo
                                echo "What port should the other OpenVPN confiuration listen to?"
                                read -p "port [`echo $(($port+1))`]: " portl
                        fi
                        until [[ -z "$portl" || "$portl" =~ ^[0-9]+$ && "$portl" -le 65535 ]]; do
                                echo "$portl: invalid port."
                                read -p "port [`echo $(($port+1))`]: " port1
                        done
                        [[ -z "$portl" ]] && portl="`echo $(($port+1))`"
                fi
        fi
        if [[ "$addvpn2" = 1 ]]; then
                if [[ "$otherprotocolarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                [[ -z "$protocoll" ]] && protocoll=1
                        else
                                echo
                                echo "Which protocol should other OpenVPN confiuration  use?"
                                echo "   1) UDP (recommended)"
                                echo "   2) TCP"
                                read -p "protocol [1]: " protocoll
                        fi
                        until [[ -z "$protocoll" || "$protocoll" =~ ^[12]$ ]]; do
                                echo "$protocol: invalid selection."
                                read -p "protocol [1]: " protocoll
                        done
                fi
                case "$protocoll" in
                        1|"")
                        protocoll=udp
                        ;;
                        2)
                        protocoll=tcp
                        ;;
                esac
        fi
        if [[ "$portl" != "$port" || "$protocoll" != "$protocol" ]]; then
                ok=1
        else
                ok=0
        fi
        until [[ "$ok" = 1 ]]; do
                if [[ "$portl" = "$port" && "$protocoll" = "$protocol" ]]; then
                        echo "The two configurations cannot use the same port number unless the protocols are different"
                        read -p "port [`echo $(($port+1))`]: " portl
                        until [[ -z "$portl" || "$portl" =~ ^[0-9]+$ && "$portl" -le 65535 ]]; do
                                echo "$portl: invalid port."
                                read -p "port [`echo $(($port+1))`]: " portl
                        done
                        [[ -z "$portl" ]] && portl="`echo $(($port+1))`"
                        echo
                        echo "Which protocol should other OpenVPN confiuration  use?"
                        echo "   1) UDP (recommended)"
                        echo "   2) TCP"
                        read -p "protocol [1]: " protocoll
                        until [[ -z "$protocoll" || "$protocoll" =~ ^[12]$ ]]; do
                                echo "$protocol: invalid selection."
                                read -p "protocol [1]: " protocoll
                        done
                        case "$protocoll" in
                                1|"")
                                protocoll=udp
                                ;;
                                2)
                                protocoll=tcp
                        ;;
                        esac
                fi
                if [[ (( "$portl" != "$port" )) || (( "$protocoll" != "$protocol" )) ]]; then
                        ok=1
                fi
        done
        if [[ "$vpntype" = "redirect-gateway" ]]; then
                if [[ "$dnsarg" == "" ]]; then
                        if [[ "$default" == "--default" ]]; then
                                [[ -z "$dns" ]] && dns="1"
                        else
                                echo
                                echo "Select a DNS server for the clients:"
                                echo "   1) Google (recommended)"
                                echo "   2) Current system resolvers"
                                echo "   3) 1.1.1.1"
                                echo "   4) OpenDNS"
                                echo "   5) Quad9"
                                echo "   6) AdGuard"
                                read -p "DNS server [1]: " dns
                        fi
                        until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
                                echo "$dns: invalid selection."
                                read -p "DNS server [1]: " dns
                        done
                fi
        else
                dns=99
        fi
        echo $othertls > /etc/openvpn-tls2-type
        echo $tls > /etc/openvpn-tls-type
        if [[ "$clientnamearg" == "" ]]; then
                if [[ "$default" == "--default" ]]; then
                        [[ -z "$unsanitized_client" ]] && unsanitized_client=client
                else
                        echo
                        echo "Enter a name for the first client:"
                        read -p "Name [client]: " unsanitized_client
                fi
        fi
        # Allow a limited set of characters to avoid conflicts
        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
        [[ -z "$client" ]] && client="client"
        echo
        echo "OpenVPN installation is ready to begin."
        # Install a firewall if firewalld or iptables are not already available
        if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
                if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                        firewall="firewalld"
                        # We don't want to silently enable firewalld, so we give a subtle warning
                        # If the user continues, firewalld will be installed and enabled during setup
                        echo "firewalld, which is required to manage routing tables, will also be installed."
                elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
                        # iptables is way less invasive than firewalld so no warning is given
                        firewall="iptables"
                fi
        fi
        if [[ "$forcearg" == "" ]]; then
                read -n1 -r -p "Press any key to continue..."
        fi
        # If running inside a container, disable LimitNPROC to prevent conflicts
        if systemd-detect-virt -cq; then
                mkdir '/etc/systemd/system/openvpn-server@server.service.d/' 2>/dev/null
                echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
        fi
        if [[ "$addvpn2" = 1 ]]; then
                echo "
[Unit]
Description=OpenVPN2 service for %I
After=network-online.target
Wants=network-online.target
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
Documentation=https://community.openvpn.net/openvpn/wiki/HOWTO

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server
ExecStart=/usr/sbin/openvpn --status /run/openvpn-server/status-server1.log --status-version 2 --suppress-timestamps --config /etc/openvpn/server/server1.conf
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
KillMode=process
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/openvpn2.service
        fi
        if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
                #apt-get update
				echo ""
                #apt-get install -y net-tools openvpn openssl ca-certificates $firewall
        elif [[ "$os" = "centos" ]]; then
                yum install -y epel-release
                yum install -y openvpn openssl ca-certificates tar $firewall
        else
                # Else, OS must be Fedora
                dnf install -y openvpn openssl ca-certificates tar $firewall
        fi
        # If firewalld was just installed, enable it
        if [[ "$firewall" == "firewalld" ]]; then
                systemctl enable --now firewalld.service
        fi
        # Get easy-rsa
        easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz'
        mkdir -p /etc/openvpn/server/easy-rsa/
        { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
        chown -R root:root /etc/openvpn/server/easy-rsa/
        cd /etc/openvpn/server/easy-rsa/
        # Create the PKI, set up the CA and the server and client certificates
        ./easyrsa init-pki
        ./easyrsa --batch build-ca nopass
        EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-server-full server nopass
        EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client" nopass
        EASYRSA_CRL_DAYS=36500 ./easyrsa gen-crl
        # Move the stuff we need
        cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
        # CRL is read with each client connection, while OpenVPN is dropped to nobody
        chown nobody:"$group_name" /etc/openvpn/server/crl.pem
        # Without +x in the directory, OpenVPN can't run a stat() on the CRL file
        chmod o+x /etc/openvpn/server/
        # Generate key for tls-crypt
        case "$tls" in
                tls-crypt|"")
                openvpn --genkey secret /etc/openvpn/server/tc.key
                ;;
                tls-crypt-v2)
                openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/tc.key
                ;;
                tls-auth)
                openvpn --genkey secret /etc/openvpn/server/tc.key
                ;;
                none)

                ;;
        esac
        if [[ "$addvpn2" = 1 ]]; then
                case "$othertls" in
                        tls-crypt|"")
                        openvpn --genkey secret /etc/openvpn/server/othertc.key
                        ;;
                        tls-crypt-v2)
                        openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/othertc.key
                        ;;
                        tls-auth)
                        openvpn --genkey secret /etc/openvpn/server/othertc.key
                        ;;
                        none)

                        ;;
                esac
        fi
        # Create the DH parameters file using the predefined ffdhe2048 group
        echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
        # Generate server.conf
        if [[ "$vpntype" = "redirect-gateway" ]]; then
                fwrule_a="firewall-cmd  --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to `echo $ip`"
                fwrule_b="firewall-cmd  --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to `echo $ip`"
                fwrule_c="firewall-cmd  --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to `echo $ip6`"
                fwrule_d="firewall-cmd  --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to `echo $ip6`"
        else
                fwrule_a="firewall-cmd  --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to `echo $ip`"
                fwrule_b="firewall-cmd  --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to `echo $ip`"
                fwrule_c="firewall-cmd  --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to `echo $ip6`"
                fwrule_d="firewall-cmd  --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to `echo $ip6`"
        fi
        echo "local $ip
port $port
proto $protocol
dev tun0
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
auth SHA512 " > /etc/openvpn/server/server.conf
                case "$tls" in
                        tls-crypt)
                        echo "tls-crypt /etc/openvpn/server/tc.key" >> /etc/openvpn/server/server.conf
                        ;;
                        tls-crypt-v2)
                        echo "tls-crypt-v2 /etc/openvpn/server/tc.key" >> /etc/openvpn/server/server.conf
                        ;;
                        tls-auth)
                        echo "tls-auth /etc/openvpn/server/tc.key 0" >> /etc/openvpn/server/server.conf
                        ;;
                        none)

                        ;;
                esac
                echo "topology $topology
client-config-dir /etc/openvpn/client
server 10.8.0.0 255.255.0.0" >> /etc/openvpn/server/server.conf
        if [[ "$addvpn2" = 1 ]]; then
                echo "local $ip
port $portl
proto $protocoll
dev tun1
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
auth SHA512 " > /etc/openvpn/server/server1.conf
                case "$othertls" in
                        tls-crypt)
                        echo "tls-crypt /etc/openvpn/server/othertc.key" >> /etc/openvpn/server/server1.conf
                        ;;
                        tls-crypt-v2)
                        echo "tls-crypt-v2 /etc/openvpn/server/othertc.key" >> /etc/openvpn/server/server1.conf
                        ;;
                        tls-auth)
                        echo "tls-auth /etc/openvpn/server/othertc.key 0" >> /etc/openvpn/server/server1.conf
                        ;;
                        none)

                        ;;
                esac
                echo "topology $topologyl
client-config-dir /etc/openvpn/client
server 10.9.0.0 255.255.0.0" >> /etc/openvpn/server/server1.conf
        fi
        # IPv6
        if [[ "$vpntype" = "redirect-gateway" ]]; then
                bypass=" bypass-dhcp"
        else
                bypass=""
        fi
        if [[ -z "$ip6" ]]; then
                echo 'push "'$vpntype' def1'$bypass'"' >> /etc/openvpn/server/server.conf
        else
                echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
                echo 'push "'$vpntype' def1 ipv6'$bypass'"' >> /etc/openvpn/server/server.conf
        fi
        if [[ "$addvpn2" = 1 ]]; then
                if [[ -z "$ip6" ]]; then
                        echo 'push "vpn-gateway def1"' >> /etc/openvpn/server/server1.conf
                else
                        echo 'server-ipv6 fddd:1194:1194:1195::/64' >> /etc/openvpn/server/server1.conf
                        echo 'push "vpn-gateway def1 ipv6"' >> /etc/openvpn/server/server1.conf
                fi
        fi
        #echo 'ifconfig-pool-persist /etc/openvpn/server/ipp.txt' >> /etc/openvpn/server/server.conf
        #if [[ "$addvpn2" = 1 ]]; then
        #       echo 'ifconfig-pool-persist /etc/openvpn/server/ipp1.txt' >> /etc/openvpn/server/server1.conf
        #fi
        # DNS
        case "$dns" in
                1|"")
                        echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
                        echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
                ;;
                2)
                        # Locate the proper resolv.conf
                        # Needed for systems running systemd-resolved
                        if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
                                resolv_conf="/run/systemd/resolve/resolv.conf"
                        else
                                resolv_conf="/etc/resolv.conf"
                        fi
                        # Obtain the resolvers from resolv.conf and use them for OpenVPN
                        grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
                                echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
                        done
                ;;
                3)
                        echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
                        echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
                ;;
                4)
                        echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
                        echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
                ;;
                5)
                        echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
                        echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
                ;;
                6)
                        echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
                        echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
                ;;
        esac
        echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify /etc/openvpn/server/crl.pem" >> /etc/openvpn/server/server.conf
        if [[ "$addvpn2" = 1 ]]; then
        echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify /etc/openvpn/server/crl.pem" >> /etc/openvpn/server/server1.conf
        fi
        if [[ "$protocol" = "udp" ]]; then
                echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
        fi
        if [[ "$addvpn2" = 1 ]]; then
                if [[ "$protocoll" = "udp" ]]; then
                        echo "explicit-exit-notify" >> /etc/openvpn/server/server1.conf
                fi
        fi
        # Enable net.ipv4.ip_forward for the system
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
        # Enable without waiting for a reboot or service restart
        echo 1 > /proc/sys/net/ipv4/ip_forward
        if [[ -n "$ip6" ]]; then
                # Enable net.ipv6.conf.all.forwarding for the system
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
                # Enable without waiting for a reboot or service restart
                echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
        fi
        if systemctl is-active --quiet firewalld.service; then
                # Using both permanent and not permanent rules to avoid a firewalld
                # reload.
                # We don't use --add-service=openvpn because that would only work with
                # the default port and protocol.
                firewall-cmd --add-port="$port"/"$protocol"
                firewall-cmd --zone=trusted --add-source=10.8.0.0/24
                firewall-cmd --permanent --add-port="$port"/"$protocol"
                firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
                # Set NAT for the VPN subnet
                `echo $fwrule_a`
                `echo $fwrule_b`
                if [[ "$addvpn2" = 1 ]]; then
                        firewall-cmd --add-port="$portl"/"$protocoll"
                        firewall-cmd --zone=trusted --add-source=10.9.0.0/24
                        firewall-cmd --permanent --add-port="$portl"/"$protocoll"
                        firewall-cmd --permanent --zone=trusted --add-source=10.9.0.0/24
                fi
                # Set NAT for the VPN
                if [[ -n "$ip6" ]]; then
                        firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
                        firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
                        `echo $fwrule_c`
                        `echo $fwrule_d`
                        if [[ "$addvpn2" = 1 ]]; then
                                firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1195::/64
                                firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1195::/64
                        fi
                fi
        else
                # Create a service to set up persistent iptables rules
                iptables_path=$(command -v iptables)
                ip6tables_path=$(command -v ip6tables)
                # nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
                # if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
                if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
                        iptables_path=$(command -v iptables-legacy)
                        ip6tables_path=$(command -v ip6tables-legacy)
                fi
                if [[ "$addvpn2" = 1 ]]; then
                        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I INPUT -d 10.8.0.0/16 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.9.0.0/16 ! -d 10.9.0.0/16 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocoll --dport $portl -j ACCEPT
ExecStart=$iptables_path -I INPUT -d 10.9.0.0/16 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D INPUT -d 10.8.0.0/16 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.9.0.0/16 ! -d 10.9.0.0/16 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocoll --dport $portl -j ACCEPT
ExecStop=$iptables_path -D INPUT -d 10.9.0.0/16 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
                        if [[ -n "$ip6" ]]; then
                                echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1195::/64 ! -d fddd:1194:1194:1195::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1195::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1195::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1195::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
                        fi
                        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
                else
                        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -j ACCEPT
ExecStart=$iptables_path -I INPUT -d 10.8.0.0/16 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -j ACCEPT
ExecStop=$iptables_path -D INPUT -d 10.8.0.0/16 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
                        if [[ -n "$ip6" ]]; then
                                echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1195::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
                        fi
                        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
                fi
                systemctl enable --now openvpn-iptables.service
        fi
        # If SELinux is enabled and a custom port was selected, we need this
        if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
                # Install semanage if not already present
                if ! hash semanage 2>/dev/null; then
                        if [[ "$os_version" -eq 7 ]]; then
                                # Centos 7
                                yum install -y policycoreutils-python
                        else
                                # CentOS 8 or Fedora
                                dnf install -y policycoreutils-python-utils
                        fi
                fi
                semanage port -a -t openvpn_port_t -p "$protocol" "$port"
        fi
        # If the server is behind NAT, use the correct IP address
        [[ -n "$public_ip" ]] && ip="$public_ip"
        # client-common.txt is created so we have a template to add further users later
        echo "client
dev tun0
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
        if [[ "$addvpn2" = 1 ]]; then
                echo "client
dev tun1
proto $protocoll
remote $ip $portl
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common1.txt
        fi
        if [[ "$vpntype" = "vpn-gateway" ]]; then
                ipl=$(grep '^local ' /etc/openvpn/server/server.conf | cut -d " " -f 2 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){2}')
                echo 'route '$ipl'.0 255.255.255.0' >> /etc/openvpn/server/client-common.txt
        fi
        if [[ "$addvpn2" = 1 ]]; then
                ipl=$(grep '^local ' /etc/openvpn/server/server.conf | cut -d " " -f 2 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){2}')
                echo 'route '$ipl'.0 255.255.255.0' >> /etc/openvpn/server/client-common1.txt
                echo 'route 10.8.0.0 255.255.0.0' >> /etc/openvpn/server/client-common1.txt
        fi
        # Enable and start the OpenVPN service
        systemctl enable --now openvpn-server@server.service
        if [[ "$addvpn2" = 1 ]]; then
                systemctl enable --now openvpn2.service
        fi
        # Generates the custom client.ovpn
        new_client
        if [[ "$addvpn2" = 1 ]]; then
                EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client"-other nopass
                new_client1
        fi
        echo
        clear
        echo "Finished!"
        echo
        echo "--------------------------------------------------------------------------------------------------------"
        echo "To get the client profile configuration just type 'sudo cat /root/$client.ovpn'"
        if [[ "$addvpn2" = 1 ]]; then
                echo "To get the client for connect-only configuration just type 'sudo cat /root/`echo $client`-other.ovpn'"
        fi
        echo "The final step is to copy the confiuration file to your device."
        echo "--------------------------------------------------------------------------------------------------------"
        echo ""
        echo "New clients can be added."
}
createarg=$(echo `echo $@` | grep -o "\-\-create=[a-zA-Z0-9./?=_-]*" | cut -c 10-)
unsanitized_clienti=$(echo $createarg)
listarg=$(echo `echo $@` | grep -o "\-\-list[a-zA-Z0-9./?=_-]*" | cut -c -6)
showarg=$(echo `echo $@` | grep -o "\-\-show=[a-zA-Z0-9./?=_-]*" | cut -c 8-)
revokearg=$(echo `echo $@` | grep -o "\-\-revoke=[a-zA-Z0-9./?=_-]*" | cut -c 10-)
uninstallarg=$(echo `echo $@` | grep -o "\-\-uninstall[a-zA-Z0-9./?=_-]*" | cut -c -11)
vpninstalled () {
        if [[ ! -e /etc/openvpn/server/server1.conf ]]; then
                addvpn2=2
        else
                addvpn2=1
        fi
        if [[ "$createarg" != "" ]]; then
                cd /etc/openvpn/server/easy-rsa/
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_clienti")
                EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client" nopass
                new_client
                if [[ "$addvpn2" = 1 ]]; then
                        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_clienti")
                        cd /etc/openvpn/server/easy-rsa/
                        EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client"-other nopass
                        new_client1
                fi
                        echo "to get the client profile configuration just type 'sudo cat /root/$client.ovpn'"
                if [[ "$addvpn2" = 1 ]]; then
                        echo "to get the client for connect-only configuration just type 'sudo cat /root/`echo $client`-other.ovpn'"
                fi
        fi
        if [[ "$listarg" != "" ]]; then
                number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
                if [[ "$number_of_clients" = 0 ]]; then
                        echo
                        echo "There are no existing clients!"
                fi
                tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
        fi
        if [[ "$showarg" != "" ]]; then
                    number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
                    client_number=$showarg
                    until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                            echo "$client_number: invalid selection."
                            read -p "Client: " client_number
                    done
                    client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$showarg"p)
					echo "----------------------------------------------------------------------------------------------------------------"
					cat /root/$client.ovpn
					echo "----------------------------------------------------------------------------------------------------------------"
                    echo
        fi
        if [[ "$revokearg" != "" ]]; then
                client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
                cd /etc/openvpn/server/easy-rsa/
                ./easyrsa --batch revoke "$client"
                EASYRSA_CRL_DAYS=36500 ./easyrsa gen-crl
                rm -f /etc/openvpn/server/crl.pem
                cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                # CRL is read with each client connection, when OpenVPN is dropped to nobody
                chown nobody:"$group_name" /etc/openvpn/server/crl.pem
                echo
                echo "$client revoked!"
        fi
        if [[ "$revokearg" != "" || "$listarg" != "" || "$createarg" != "" || "$showarg" != "" ]]; then
                option=5
        else
                if [[ "$uninstallarg" = "" ]]; then
                        echo "OpenVPN is already installed. use the installer with the arg --help to see the automation options"
                        echo
                        echo "Select an option:"
                        echo "   1) Add a new client"
			echo "   2) Show a client configuration file"
                        echo "   3) Revoke an existing client"
                        echo "   4) Remove OpenVPN"
                        echo "   5) Exit"
                        read -p "Option: " option
                        until [[ "$option" =~ ^[1-5]$ ]]; do
                                echo "$option: invalid selection."
                                read -p "Option: " option
                        done
                else
                        option=4
                fi
        fi
        case "$option" in
                1)
                        if [[ ! -e /etc/openvpn/server/server1.conf ]]; then
                                addvpn2=2
                        else
                                addvpn2=1
                        fi
                        echo
                        echo "Provide a name for the client:"
                        read -p "Name: " unsanitized_clienti
                        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_clienti")
                        while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
                                echo "$client: invalid name."
                                read -p "Name: " unsanitized_clienti
                                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_clienti")
                        done
                        cd /etc/openvpn/server/easy-rsa/
                        EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client" nopass
                        # Generates the custom client.ovpn
                        new_client
                        if [[ "$addvpn2" = 1 ]]; then
                                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_clienti")
                                cd /etc/openvpn/server/easy-rsa/
                                EASYRSA_CERT_EXPIRE=36500 ./easyrsa build-client-full "$client"-other nopass
                                new_client1
                        fi
						echo "--------------------------------------------------------------------------------------------------------"
						echo "To get the client profile configuration just type 'sudo cat /root/$client.ovpn'"
						if [[ "$addvpn2" = 1 ]]; then
								echo "To get the client for connect-only configuration just type 'sudo cat /root/`echo $client`-other.ovpn'"
						fi
						echo "The final step is to copy the confiuration file to your device."
						echo "--------------------------------------------------------------------------------------------------------"
                ;;
				2)
                        if [[ ! -e /etc/openvpn/server/server1.conf ]]; then
                                addvpn2=2
                        else
                                addvpn2=1
                        fi
                        # This option could be documented a bit better and maybe even be simplified
                        # ...but what can I say, I want some sleep too
                        number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
                        if [[ "$number_of_clients" = 0 ]]; then
                                echo
                                echo "There are no existing clients!"
                                exit
                        fi
                        echo
                        echo "Select the client to show it's file:"
                        tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                        read -p "Client: " client_number
                        until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                                echo "$client_number: invalid selection."
                                read -p "Client: " client_number
                        done
                        client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
						echo "----------------------------------------------------------------------------------------------------------------"
						cat /root/$client.ovpn
						echo "----------------------------------------------------------------------------------------------------------------"
                        echo
				;;
                3)
                        if [[ ! -e /etc/openvpn/server/server1.conf ]]; then
                                addvpn2=2
                        else
                                addvpn2=1
                        fi
                        # This option could be documented a bit better and maybe even be simplified
                        # ...but what can I say, I want some sleep too
                        number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
                        if [[ "$number_of_clients" = 0 ]]; then
                                echo
                                echo "There are no existing clients!"
                                exit
                        fi
                        echo
                        echo "Select the client to revoke:"
                        tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                        read -p "Client: " client_number
                        until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                                echo "$client_number: invalid selection."
                                read -p "Client: " client_number
                        done
                        client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
                        echo
                        read -p "Confirm $client revocation? [y/N]: " revoke
                        until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
                                echo "$revoke: invalid selection."
                                read -p "Confirm $client revocation? [y/N]: " revoke
                        done
                        if [[ "$revoke" =~ ^[yY]$ ]]; then
                                cd /etc/openvpn/server/easy-rsa/
                                ./easyrsa --batch revoke "$client"
                                EASYRSA_CRL_DAYS=36500 ./easyrsa gen-crl
                                rm -f /etc/openvpn/server/crl.pem
                                cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                                # CRL is read with each client connection, when OpenVPN is dropped to nobody
                                chown nobody:"$group_name" /etc/openvpn/server/crl.pem
                                echo
                                echo "$client revoked!"
                        else
                                echo
                                echo "$client revocation aborted!"
                        fi
                ;;
                4)
                        if [[ ! -e /etc/openvpn/server/server1.conf ]]; then
                                addvpn2=2
                        else
                                addvpn2=1
                        fi
                        echo
                        if [[ "$forcearg" == "" ]]; then
                                read -p "Confirm OpenVPN removal? [y/N]: " remove
                        else
                                remove=y
                        fi
                        until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                                echo "$remove: invalid selection."
                                read -p "Confirm OpenVPN removal? [y/N]: " remove
                        done
                        if [[ "$remove" =~ ^[yY]$ ]]; then
                                port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                                protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                                if [[ "$addvpn2" = 1 ]]; then
                                        port1=$(grep '^port ' /etc/openvpn/server/server1.conf | cut -d " " -f 2)
                                        protocoll=$(grep '^proto ' /etc/openvpn/server/server1.conf | cut -d " " -f 2)
                                fi
                        if systemctl is-active --quiet firewalld.service; then
                                        ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
                                        # Using both permanent and not permanent rules to avoid a firewalld reload.
                                        firewall-cmd --remove-port="$port"/"$protocol"
                                        firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
                                        firewall-cmd --permanent --remove-port="$port"/"$protocol"
                                        firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
                                        if [[ "$addvpn2" = 1 ]]; then
                                                firewall-cmd --remove-port="$portl"/"$protocoll"
                                                firewall-cmd --zone=trusted --remove-source=10.9.0.0/24
                                                firewall-cmd --permanent --remove-port="$portl"/"$protocoll"
                                        firewall-cmd --permanent --zone=trusted --remove-source=10.9.0.0/24
                                        fi
                                        firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
                                        firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
                                        if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
                                                ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
                                                firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                                                firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                                                if [[ "$addvpn2" = 1 ]]; then
                                                        firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1195::/64
                                                        firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1195::/64
                                                fi
                                                firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                                                firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                                        fi
                                else
                                        systemctl disable --now openvpn-iptables.service
                                        rm -f /etc/systemd/system/openvpn-iptables.service
                                fi
                                if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
                                        semanage port -d -t openvpn_port_t -p "$protocol" "$port"
                                fi
                                systemctl disable --now openvpn-server@server.service
                                if [[ "$addvpn2" = 1 ]]; then
                                        systemctl disable --now openvpn2.service
                                fi
                                rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
                                        if [[ "$addvpn2" = 1 ]]; then
                                                rm -f /etc/systemd/system/openvpn-server1@server.service.d/disable-limitnproc.conf
                                        fi
                                rm -f /etc/sysctl.d/99-openvpn-forward.conf
                                rm -f /etc/openvpn/client/*
                                if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
                                        rm -rf /etc/openvpn/server
                                        #apt-get remove --purge -y openvpn
                                else
                                        # Else, OS must be CentOS or Fedora
                                        yum remove -y openvpn
                                        rm -rf /etc/openvpn/server
                                fi
                                echo
                                echo "OpenVPN removed!"
                        else
                                echo
                                echo "OpenVPN removal aborted!"
                        fi
                ;;
                5)
                        exit
                ;;
        esac
}
helparg=$(echo `echo $@` | grep -o "\-\-help" | cut -c -6)
until [[ $option == 5 ]]; do
if [[ $option == 5 ]]; then
	exit
fi
if [[ "$helparg" == "" ]]; then
        if [[ ! -e /etc/openvpn/server/server.conf ]]; then
		clear
                installvpn
        else
                vpninstalled
        fi
else

scriptpath=$0
echo "-----------------------------------------------------------------------------------"
echo "------------------Welcome to this OpenVPN road warrior installer!------------------"
echo "-----------------------------------------------------------------------------------"
echo "Usage: sudo bash openvpn-install.sh"
echo "   OR: sudo bash openvpn-install.sh 'options'"
echo ""
echo "note: all the options are case sensitive, characters '=','--' are necessary."
echo "First run Options:"
echo " --help                    : print this page and exit."
echo " --default                 : go with the default with everything that isn't specified."
echo " --ip-host=IP-HOST         : specify the public ip OR the Hostname name that the clients will use to look for this server."
echo " --protocol=(tcp|udp)      : specify the protocol for the vpn server (this is only for the first configuration), default is udp."
echo " --port=NUM                : specify the port number for the vpn server (this is only for the first configuration), default is 1194."
echo " --vpntype=NUM             : specify the vpn type (1)change-the-ip or (2)connect-only or (3)both"
echo " --topology=NUM            : specify the topology type (1)subnet, (2)net30,(this is only for the first configuration)"
echo " --otherport=NUM           : specify the port number for the second vpn configutation-"
echo "                             default is the port for the first configuration + '1'"
echo " --otherprotocol=(tcp|udp) : specify the protocol for the second vpn configuration, default is udp."
echo " --othertopology=NUM       : specify the topology type for the second sonfiguration (1)subnet, (2)net30,"
echo " --dns=NUM                 : specify the DNS server for the redirect-gateway configuration"
echo " --clientname=NAME         : specify the name of the first client to be created"
echo " --force                   : when using the option --default the user will be asked to confirm the installation "
echo "                             type --force to avoid that"
echo " --tls=NUM                 : the tls type (1)tls-crypt-v2, (2)tls-crypt, (3)tls-auth or (4)none, the default is (1)"
echo " --othertls=NUM            : the tls type for the other vpn configuration"
echo " --extraoptions=NUM        : show the extra setup options (1)no (2)yes , default is (1)no"
echo
echo "if the VPN installed:"
echo " --show=NUM                : show a client confiuration file"
echo " --create=NAME             : create a new client."
echo " --list                    : list all existing client."
echo " --revoke=NUM              : revoke an existing client by it's number (use --list to see the numbers of the clients)."
echo " --uninstall               : Remove OpenVPN, use with --force to skip the confirmation."
echo
echo "all the unknown or unused options will be ignored"
echo "the normal setup 'without any options' have enough details"
exit
fi
done
echo ""
echo ""
echo ""
