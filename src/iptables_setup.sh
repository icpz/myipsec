#!/usr/bin/env bash

MY_CHAIN="myipsec_chain"

function is_root() {
    [ $UID -eq 0 ]
}

function iptables_chain_exists() {
    local chain_name="$1"; shift
    [ $# -eq 1 ] && local table_name="-t $1"
    iptables $table_name -n --list "$chain_name" > /dev/null 2>&1
}

function iptables_setup() {
    if iptables_chain_exists $MY_CHAIN raw; then
        echo chain $MY_CHAIN in raw already exists.
        return
    fi

    iptables -t raw -N $MY_CHAIN
    iptables -t raw -A $MY_CHAIN -j NFQUEUE
    iptables -t raw -A $MY_CHAIN -j RETURN

    iptables -t raw -I PREROUTING -j $MY_CHAIN
    iptables -t raw -I OUTPUT -j $MY_CHAIN

    if iptables_chain_exists $MY_CHAIN filter; then
        echo chain $MY_CHAIN in raw already exists.
        return
    fi

    iptables -N $MY_CHAIN
    iptables -A $MY_CHAIN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
    iptables -A $MY_CHAIN -j RETURN
    
    iptables -I INPUT -j $MY_CHAIN
    iptables -I OUTPUT -j $MY_CHAIN
}

function iptables_unsetup() {
    iptables-save | grep -v -- "-j $MY_CHAIN" | iptables-restore
    iptables -t raw -F $MY_CHAIN
    iptables -t raw -X $MY_CHAIN
    iptables -F $MY_CHAIN
    iptables -X $MY_CHAIN
}

function usage() {
    echo "Usage $0 setup|reset"
    echo "This script is used for setting up the iptables."
    echo "It's recommended to run this script after starting \`myipsec'"
}

if ! is_root; then
    echo 'This script must exec by root'
    exit;
fi

case $1 in
    setup)
        iptables_setup;
        echo "iptables has been setup"
        ;;
    reset)
        iptables_unsetup;
        echo "iptables has been reset"
        ;;

    *)
        usage;
        ;;
esac

