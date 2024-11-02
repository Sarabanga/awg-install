#!/bin/bash

# AmneziaWG server installer

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

CONFIG_DIR="/root/configs"

function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

function checkVirt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo "OpenVZ is not supported"
        exit 1
    fi

    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo "LXC is not supported (yet)."
        echo "AmneziaWG can technically run in an LXC container,"
        echo "but the kernel module has to be installed on the host,"
        echo "the container has to be run with some specific parameters"
        echo "and only the tools need to be installed in the container."
        exit 1
    fi
}

function checkOS() {
    source /etc/os-release
    OS="${ID}"
    if [[ ${OS} == "ubuntu" ]]; then
        RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
        if [[ ${RELEASE_YEAR} -lt 22 ]]; then
            echo "Please use Ubuntu 24.04 to run this script."
            exit 1
        fi
    else
        echo "Please use Ubuntu 24.04 to run this script."
        exit 1
    fi
}

function initialCheck() {
    isRoot
    checkVirt
    checkOS
}

function installQuestions() {
    echo "Welcome to the AmneziaWG installer!"
    echo ""
    echo "I need to ask you a few questions before starting the setup."
    echo "You can keep the default options and just press enter if you are ok with them."
    echo ""

    # Detect public IPv4 address and pre-fill for the user
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    read -rp "IPv4 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # Detect public interface and pre-fill for the user
    SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
        read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
    done

    until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
        read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_WG_NIC
    done

    until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
        read -rp "Server AmneziaWG IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
    done

    # Generate random number within private ports range
    RANDOM_PORT=$(shuf -i49152-65535 -n1)
    until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
    done

    # Adguard DNS by default
    until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "First DNS resolver to use for the clients: " -e -i 94.140.14.14 CLIENT_DNS_1
    done
    until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Second DNS resolver to use for the clients (optional): " -e -i 94.140.15.15 CLIENT_DNS_2
        if [[ ${CLIENT_DNS_2} == "" ]]; then
            CLIENT_DNS_2="${CLIENT_DNS_1}"
        fi
    done

    until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
        echo -e "\nAmneziaWG uses a parameter called AllowedIPs to determine what is routed over the VPN."
        read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0' ALLOWED_IPS
        if [[ ${ALLOWED_IPS} == "" ]]; then
            ALLOWED_IPS="0.0.0.0/0"
        fi
    done

    echo ""
    echo "Okay, that was all I needed. We are ready to setup your AmneziaWG server now."
    echo "You will be able to generate a client at the end of the installation."
    read -n1 -r -p "Press any key to continue..."
}

function installAmneziaWG() {
    # Run setup questions first
    installQuestions

apt update
apt install mc git make build-essential wireguard wireguard-tools -y
mkdir /root/AWG
cd /root/AWG
git clone https://github.com/Sarabanga/amneziawg-tools
git clone https://github.com/Sarabanga/amneziawg-go
git clone https://github.com/Sarabanga/wireguard-install

wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -xvf go1.21.0.linux-amd64.tar.gz
mv go /usr/local
export PATH=$PATH:/usr/local/go/bin
go version
cd /root/AWG/amneziawg-tools/src
make
make install
cd /root/AWG/amneziawg-go/
make
cp /root/AWG/amneziawg-go/amneziawg-go /bin

    SERVER_PRIV_KEY=$(awg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

    # Save AmneziaWG settings
    echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/amnezia/amneziawg/params

    # Add server interface
    echo "[Interface]
Address = ${SERVER_WG_IPV4}/8
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = 7
Jmin = 50
Jmax = 1000
S1 = 66
S2 = 29
H1 = 2144406505
H2 = 275998647
H3 = 1346512134
H4 = 667835831
" >"/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"

    # Setup iptables rules
    echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"

    # Enable routing on the server
    echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf

    sysctl --system

    systemctl start "awg-quick@${SERVER_WG_NIC}"
    systemctl enable "awg-quick@${SERVER_WG_NIC}"

    newClient
    echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

    # Check if AmneziaWG is running
    systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"
    WG_RUNNING=$?

    # AmneziaWG might not work if we updated the kernel. Tell the user to reboot
    if [[ ${WG_RUNNING} -ne 0 ]]; then
        echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
        echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_WG_NIC}${NC}"
        echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
    else # AmneziaWG is running
        echo -e "\n${GREEN}AmneziaWG is running.${NC}"
        echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_WG_NIC}\n\n${NC}"
        echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
    fi
}

function newClient() {

   echo
   echo "Provide a name for the client:"
   read -p "Name: " unsanitized_client
   # Allow a limited lenght and set of characters to avoid conflicts
   client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
   while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf; do
    echo "$client: invalid name."
    read -p "Name: " unsanitized_client
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
   done
   echo $client

AWG_IP_RANGE=$(echo ${SERVER_WG_IPV4} | awk -F'.' {'print $1"."$2"."$3'})

#IP=$(curl -s ifconfig.io)
IP=${SERVER_PUB_IP}
        # Given a list of the assigned internal IPv4 addresses, obtain the lowest still
        # available octet. Important to start looking at 2, because 1 is our gateway.
        octet=2
        while grep AllowedIPs /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
                (( octet++ ))
        done
        # Don't break the WireGuard configuration in case the address space is full
        if [[ "$octet" -eq 255 ]]; then
                echo "253 clients are already configured. The WireGuard internal subnet is full!"
                exit
        fi
#        key=$(wg genkey)
#        psk=$(wg genpsk)
        # Configure client in the server
        cat << EOF >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
# BEGIN_PEER $client
[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = $(awg genpsk)
AllowedIPs = $AWG_IP_RANGE.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
        # Create client configuration
        cat << EOF > /root/"$client".conf
[Interface]
Address = $AWG_IP_RANGE.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = 8.8.8.8, 1.0.0.1
PrivateKey = ${SERVER_PRIV_KEY}

Jc = 7
Jmin = 50
Jmax = 1000
S1 = 66
S2 = 29
H1 = 2144406505
H2 = 275998647
H3 = 1346512134
H4 = 667835831

[Peer]
PublicKey = $(grep PrivateKey /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf | cut -d " " -f 3 | awg pubkey)
PresharedKey = $(awg genpsk)
AllowedIPs = 0.0.0.0/0
Endpoint = $IP:$(grep ListenPort /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
/usr/bin/awg syncconf ${SERVER_WG_NIC} <(/usr/bin/awg-quick strip ${SERVER_WG_NIC})

}

function listClients() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf")
    if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    grep -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    echo ""
    echo "Select the existing client you want to revoke"
    grep -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '

    if [[ -n "${CLIENT_NAME}" ]]; then
        echo "Using provided client name: ${CLIENT_NAME}"
    else
        until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
            read -rp "Enter the client name to revoke: " -e CLIENT_NAME
            CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf")

            if [[ ${CLIENT_EXISTS} == '0' ]]; then
                echo ""
                echo -e "${ORANGE}A client with the specified name does not exist, please choose an existing client name.${NC}"
                echo ""
            fi
        done
    fi

    # remove [Peer] block matching $CLIENT_NAME
    sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"

    # remove generated client file
    rm -f "${CONFIG_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # restart amneziawg to apply changes
    awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
    echo ""
    echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
    echo -e "${ORANGE}Please backup the /etc/amnezia directory if you want to keep your configuration files.\n${NC}"
    read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
    REMOVE=${REMOVE:-n}
    if [[ $REMOVE == 'y' ]]; then
        checkOS

        systemctl stop "awg-quick@${SERVER_WG_NIC}"
        systemctl disable "awg-quick@${SERVER_WG_NIC}"

        apt-get remove -y amneziawg qrencode

        rm -rf /etc/amnezia
        rm -f /etc/sysctl.d/awg.conf

        # Reload sysctl
        sysctl --system

        # Check if AmneziaWG is running
        systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"
        WG_RUNNING=$?

        if [[ ${WG_RUNNING} -eq 0 ]]; then
            echo "AmneziaWG failed to uninstall properly."
            exit 1
        else
            echo "AmneziaWG uninstalled successfully."
            exit 0
        fi
    else
        echo ""
        echo "Removal aborted!"
    fi
}

function manageMenu() {
    echo "It looks like AmneziaWG is already installed."
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new user"
    echo "   2) List all users"
    echo "   3) Revoke existing user"
    echo "   4) Uninstall AmneziaWG"
    echo "   5) Exit"
    until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
        read -rp "Select an option [1-5]: " MENU_OPTION
    done
    case "${MENU_OPTION}" in
    1)
        newClient
        ;;
    2)
        listClients
        ;;
    3)
        revokeClient
        ;;
    4)
        uninstallWg
        ;;
    5)
        exit 0
        ;;
    esac
}

# Check for root, virt, OS...
initialCheck

# Check if AmneziaWG is already installed and load params
if [[ -e /etc/amnezia/amneziawg/params ]]; then
    source /etc/amnezia/amneziawg/params
    if [[ $1 == "non-interactive" ]]; then
        MODE="$2"
        CLIENT_NAME="$3"
        CLIENT_WG_IPV4="$4"

        case "$MODE" in
            1)
                newClient
                ;;
            3)
                revokeClientW
                ;;
            *)
                echo "Invalid mode"
                exit 1
                ;;
        esac
    else
        manageMenu
    fi
else
    installAmneziaWG
fi

