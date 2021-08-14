#!/bin/bash

set -o errexit

RESET=$'\e[0m'
BOLD=$'\e[1m'
RED=$'\e[31m'
BRED=$'\e[31;1m'
GREEN=$'\e[32m'
BGREEN=$'\e[32;1m'
YELLOW=$'\e[33m'
BYELLOW=$'\e[33;1m'


warn() {
    echo -n $BRED >&2
    echo "$@" >&2
    echo $RESET >&2
}

die() {
    warn "$@"
    exit 1
}


echo
echo "${BGREEN}Beldex-launcher to deb conversion script$RESET"
echo "${BGREEN}======================================$RESET"
echo

declare -A pkgnames=([lsb_release]=lsb-release)
for prog in jq curl gpg lsb_release; do
    if ! which $prog &>/dev/null; then
        die "Could not find '$prog' which we require for this script.

Try installing it using:

    sudo apt install ${pkgnames[$prog]:-$prog}

and then run this script again."
    fi
done

if [ $UID -ne 0 ]; then
    die "You need to run this script as root (e.g. via sudo)"
fi

need_help=
bad_args=
lldata=/opt/beldex-launcher/var
user=
datadir=
no_proc_check=
overwrite=
distro=
service=beldexd.service

while [ "$#" -ge 1 ]; do
    arg="$1"
    shift
    if [[ $arg =~ ^--help ]]; then
        need_help=1
    elif [[ $arg =~ ^--no-process-checks ]]; then
        no_proc_check=1
    elif [[ $arg =~ ^--service=([a-zA-Z0-9@_-]+)$ ]]; then
        service="${BASH_REMATCH[1]}"
    elif [[ $arg =~ ^--datadir=(.*)$ ]]; then
        datadir="${BASH_REMATCH[1]}"
    elif [[ $arg =~ ^--lldata=(.*)$ ]]; then
        lldata="${BASH_REMATCH[1]}"
    elif [[ $arg =~ ^--distro=(.*)$ ]]; then
        distro="${BASH_REMATCH[1]}"
    elif [[ $arg =~ ^--overwrite$ ]]; then
        overwrite=1
    elif [[ $arg =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        user="$arg"
    else
        bad_args="${bad_args}"$'\n'"Unknown option '$arg'"
    fi
done

if [ -z "$user$need_help" ]; then
    bad_args="${bad_args}"$'\n'"No beldex launcher username specified!"
fi

if [ -n "${need_help}${bad_args}" ]; then
    if [ -n "${bad_args}" ]; then
        echo -e "${RED}Invalid arguments:${bad_args}${RESET}\n\n" >&2
    fi
    cat <<HELP >&2
Usage: $0 [OPTIONS] USERNAME

This script migrates a standard beldex-launcher installation to use debian/ubuntu
packages.  You should run this script on a live, active beldex-launcher server;
this scripts connects to the running beldex-launcher and beldexd to make sure
everything is as expected during the migration.

This script has one required argument: the username where beldex-launcher is
installed.  This is typically 'mnode':

    $0 mnode

but if you installed under a different username you should specify that instead.

The script asks for confirmation before undertaking actions so is safe to run
and cancel partway through without affecting your existing beldex-launcher
installation.

If anything goes wrong please contact Beldex staff with any output or errors that
are shown by this script.

Extra options (for typical beldex-launcher installs these are not needed):

    --service=servicename   -- specifies a beldex-launcher systemd service name
                               if different from 'beldexd.service'
    --datadir=/path/to/beldex -- path to the beldex-launcher data directory if not
                               the default /home/<user>/.beldex
    --lldata=/path/to/beldex-launcher/var -- path to the beldex launcher "var"
                               directory if not the default.
    --overwrite             -- run the script even if /var/lib/beldex already
                               exists.  ${RED}Use caution!$RESET
    --no-process-checks     -- allow the migration to run even if beldexd/ss/
                               belnet processes are still running after
                               stopping beldex-launcher.
    --distro=<dist>         -- allows overriding the detected Ubuntu/Debian
                               distribution (default: $(lsb_release -sc))
HELP

    echo; echo
    exit 1
fi

homedir=$(getent passwd $user | cut -f6 -d:)

if ! [ -d "$homedir" ]; then
    die "User $user and/or home directory ($homedir) does not exist; check the username and try again (try $0 --help for details)"
fi

if [ -z "$datadir" ]; then datadir="$homedir/.beldex"; fi

if ! [ -d "$datadir" ]; then
    die "$datadir does not exist; is $user the user that beldex-launcher runs as?"
fi

#if ! [ -d /opt/beldex-launcher/var ]; then
#    die "/opt/beldex-launcher/var does not exist; is beldex-launcher installed?"
#fi

if [ -z "$distro" ]; then distro=$(lsb_release -sc); fi
if [ "$distro" == "bullseye" ]; then distro=sid; fi

if ! [[ "$distro" =~ ^(xenial|bionic|eoan|focal|stretch|buster|sid)$ ]]; then
    die "Don't know how to install debs for '$distro'.$RESET

Your system reports itself as:
$(lsb_release -idrc)

If this is being reported incorrectly you can try running this script with
'--distro=<dist>' where <dist> is one of:

    xenial  -- Ubuntu 16.04 *
    bionic  -- Ubuntu 18.04
    eoan    -- Ubuntu 19.10 *
    focal   -- Ubuntu 20.04
    stretch -- Debian 9     *
    buster  -- Debian 10
    sid     -- Debian testing or Debian sid

* - upgrading from these is recommended as future version support for service
    node is not guaranteed.
"
fi


cat <<START
Okay, let's get started.  First I'm going to run some checks against your
current system to make sure beldex-launcher is running (I'll start it if it isn't
already running), and then check the configuration to make sure it looks good.

If everything checks out I'll show you a summary of the configuration details I
found, and ask you again for confirmation.  Once you accept, I'll install the
debs, move the database files into place, and update the new debian package
configuration files.

This process typically takes only a few seconds.

If you're ready to get started, press Enter.  If you want to cancel, hit
Ctrl-C.
START

read

existing=
if systemctl is-active -q beldex-node belnet-router beldex-storage-server; then
    existing="systemd services ${BOLD}beldex-node$RESET, ${BOLD}belnet-router$RESET, and/or ${BOLD}beldex-storage-server$RESET are
already running!'"
elif [ -d /var/lib/beldex ] && [ -z "$overwrite" ]; then
    existing="$BOLD/var/lib/beldex$RESET already exists!"
fi

if [ -n "$existing" ]; then
    echo "$existing

If you intend to overwrite an existing deb installation then you must stop them
using:

    sudo systemctl disable --now beldex-node belnet-router beldex-storage-server

and then must rerun this script adding the ${BOLD}--overwrite$RESET option.  Be
careful: this will overwrite any existing configuration and data (including
your MN keys) of the existing deb installation!
"
    die "Aborting because an existing deb installation was already detected."
fi

if systemctl is-active -q "$service"; then
    echo $'beldex launcher is currently running, good.'
elif systemctl is-enabled -q "$service"; then
    echo "beldex launcher ($service) is currently stopped."
    if read -p $'Press Enter to start it, or Ctrl-C to abort.\n'; then
        if ! systemctl start "$service"; then
            die "Failed to start beldex launcher!  Check its status with 'systemctl status $service'"
        fi
    fi
else
    die "beldex launcher does not look like it is currently enabled; check 'systemctl status $service'"
fi


for ((i = 0; i <= 10; i++)); do
    if [ -f "$lldata/pids.json" ]; then break; fi
    if [ "$i" == 10 ]; then
        die "Timed out waiting for beldex launcher to create $lldata/pids.json; giving up"
    fi
    echo "Waiting for beldex-launcher to create $lldata/pids.json"
    sleep 1  # Because beldex-launcher doesn't signal actual startup to systemd nicely
done

lljson=$(<$lldata/pids.json)

_dd=$(jq -r .runningConfig.blockchain.data_dir <<<$lljson)
_rpc=$(jq -r .runningConfig.blockchain.rpc_port <<<$lljson)

if [ -z "$_dd" ] || [ -z "$_rpc" ]; then
    die "Failed to extract beldex data directory and rpc port from beldex-launcher pids.json"
fi

if [ "$_dd" != "$datadir" ]; then
    die "beldex-launcher reports a non-standard data directory $_dd (instead of $datadir).  If this is correct, re-run this script with --datadir='$_dd' to use it."
fi

echo -n "Connecting to beldexd to check current status..."

# Gets a value from a command, retrying (with a 1s sleep) if it fails.
get_value() {
    local TRIES=$1
    shift
    local val=
    local tries=0
    while [ -z "$val" ]; do
        if ! val=$("$@"); then
            val=
            if ((++tries >= $TRIES)); then
                die "Too many failures trying to reach beldexd, aborting"
            fi
            echo "Failed to reach beldexd, retrying in 1s..." >&2
            sleep 1
        fi
    done
    echo "$val"
}


declare -A json
json[getinfo]=$(get_value 30 curl -sS http://localhost:$_rpc/get_info)
json[pubkeys]=$(get_value 3 curl -sSX POST http://localhost:$_rpc/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_master_node_key"}')
json[privkeys]=$(get_value 3 curl -sSX POST http://localhost:$_rpc/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_master_node_privkey"}')
echo " done."

# Get the privkey off disk (to compare)
privkey_disk=$(od -An -tx1 -v $datadir/key | tr -d ' \n')
privkey_rpc=$(jq -r .result.master_node_privkey <<<"${json[privkeys]}")

if [ "$privkey_disk" != "$privkey_rpc" ]; then
    die "Error: your MN private key obtained from beldexd doesn't match the one on disk!"
fi

if ! [ -f "$datadir/lmdb/data.mdb" ]; then
    die "Error: Expected blockchain database $datadir/lmdb/data.mdb does not exist"
fi

lmdbsize=$(stat --printf=%s $datadir/lmdb/data.mdb)
getinfosize="$(jq -r .database_size <<<"${json[getinfo]}")"
if [ "$lmdbsize" != "$getinfosize" ]; then
    die "Error: data.mdb size on disk ($lmdbsize) doesn't match size returned by beldexd ($getinfosize); perhaps the database path is incorrect?"
fi

ip_public=$(jq -r .runningConfig.launcher.publicIPv4 <<<"$lljson")
beldexd_rpc=$(jq -r .runningConfig.blockchain.rpc_port <<<"$lljson")
beldexd_p2p=$(jq -r .runningConfig.blockchain.p2p_port <<<"$lljson")
beldexd_qnet=$(jq -r .runningConfig.blockchain.qun_port <<<"$lljson")
ss_data=$(jq -r .runningConfig.storage.data_dir <<<"$lljson")
ss_http=$(jq -r .runningConfig.storage.port <<<"$lljson")
ss_lmq=$(jq -r .runningConfig.storage.lmq_port <<<"$lljson")
ss_listen=$(jq -r .runningConfig.storage.ip <<<"$lljson")
belnet_data=$(jq -r .runningConfig.network.data_dir <<<"$lljson")
belnet_ip=${ip_public} # Currently beldex-launcher doesn't support specifying this separately
belnet_port=$(jq -r .runningConfig.network.public_port <<<"$lljson")
belnet_simple=

if [ "$belnet_ip" != "$ip_public" ]; then
    die "Unsupported configuration anamoly detected: publicIPv4 ($ip_public) is not the same as belnet's public IP ($belnet_ip)"
fi

# Belnet configuration: if the public IP is a local system IP then we can just produce:
#
# [bind]
# IP=port
#
# If it isn't then rather than muck around trying to figure out the default interface, we'll just produce:
#
# [router]
# public-ip=IP
# public-port=port
# [bind]
# 0.0.0.0=port
#
# which will listen on all interfaces, and use the public-ip value to advertise itself to the network.
if [[ "$(ip -o route get ${ip_public})" =~ \ dev\ lo\  ]]; then
    belnet_simple=1
fi

if [ "$ss_listen" != "0.0.0.0" ]; then
    # Not listening on 0.0.0.0 is a bug (because it means SS isn't accessible over belnet), unless you have
    # some exotic packet forwarding set up locally.
    warn "WARNING: storage server listening IP will be changed from $ss_listen to 0.0.0.0 (all addresses)" >&2
fi

custom_ll_warning=
if [ -f /etc/beldex-launcher/launcher.ini ]; then
    custom_ll_warning=/etc/beldex-launcher/launcher.ini
elif [ -f $(dirname $(which beldex-launcher))/beldex-launcher.ini ]; then
    custom_ll_warning=$(dirname $(which beldex-launcher))/beldex-launcher.ini
fi

if [ -n "$custom_ll_warning" ]; then
    custom_ll_warning="${BRED}WARNING:$RESET you have a custom launcher.ini file at ${custom_ll_warning}.
If you have customized any settings that aren't listed above then you will need
to update the configuration files (shown below) after migration.
"
fi

cat <<DETAILS

${BGREEN}Summary: this script detected the following settings to migrate:${RESET}

beldexd:
- master node pubkey: $BOLD$(jq -r .result.master_node_pubkey <<<"${json[pubkeys]}")$RESET
- data directory: $BOLD$datadir$RESET (=> $BOLD/var/lib/beldex$RESET)
- p2p/rpc/qnet ports: $BOLD$beldexd_p2p/$beldexd_rpc/$beldexd_qnet$RESET

beldex-storage-server:
- data directory: $BOLD$ss_data$RESET (=> $BOLD/var/lib/beldex/storage$RESET)
- public IP: $BOLD$ip_public$RESET
- HTTP/LokiMQ ports: $BOLD$ss_http/$ss_lmq$RESET

belnet:
- data directory: $BOLD$belnet_data$RESET (=> $BOLD/var/lib/belnet$RESET)
- public IP: $BOLD$ip_public$RESET
- port: $BOLD$belnet_port$RESET

$custom_ll_warning
After migration you can change configuration settings through the files:
    $BOLD/etc/beldex/beldex.conf$RESET
    $BOLD/etc/beldex/storage.conf$RESET
    $BOLD/etc/beldex/belnet-router.conf$RESET

DETAILS

read -p $'Check the above and, if all looks good, press enter to begin the migration or Ctrl-C to abort...'

systemctl_verbose() {
    action="$1"
    shift
    echo -n "$action..."
    "$@"
    echo ' done.'
}

systemctl_verbose 'Stopping beldex-launcher' \
    systemctl stop "${service}"
if systemctl -q is-active "${service}"; then
    die "beldex-launcher is still running!"
fi

if [ -z "$no_proc_check" ] && pidof -q beldexd beldex-storage belnet; then
    die $'Stopped storage server, but one or more of beldexd/beldex-storage/belnet is still running.

(If you know that you have other beldexd/ss/belnets running on this machine then rerun this script with the --no-process-checks option)'
fi

systemctl_verbose 'Disabling beldex-launcher automatic startup' \
    systemctl disable "${service}"

systemctl_verbose 'Temporarily masking beldex services from startup until we are done migrating' \
    systemctl mask beldex-node.service belnet-router.service beldex-storage-server.service

if ! [ -f /etc/apt/sources.list.d/beldex.list ]; then
    echo 'Adding deb repository to /etc/apt/sources.list.d/beldex.list'
    echo "deb https://deb.imaginary.stream $distro main" >/etc/apt/sources.list.d/beldex.list
else
    echo '/etc/apt/sources.list.d/beldex.list already exists, not replacing it.'
fi

echo 'Adding repository signing key and updating packages'
curl -s https://deb.imaginary.stream/public.gpg | apt-key add -

apt-get update

echo 'Installing beldex packages'

apt-get -y install beldexd beldex-storage-server belnet-router

echo "${GREEN}Moving beldexd data files to /var/lib/beldex$RESET"
echo "${GREEN}========================================$RESET"
if ! [ -d /var/lib/beldex/lmdb ]; then
    mkdir -v /var/lib/beldex/lmdb
    chown -v _beldex:_beldex /var/lib/beldex/lmdb
fi
cp -vf "$datadir"/key* /var/lib/beldex # Copy to be extra conservative with the keys
mv -vf "$datadir"/lmdb/*.mdb /var/lib/beldex/lmdb
mv -vf "$datadir"/bns.db* /var/lib/beldex
chown -v _beldex:_beldex /var/lib/beldex/{bns.db*,key*,lmdb/*.mdb}

echo "${GREEN}Updating beldexd configuration in /etc/beldex/beldex.conf$RESET"
echo "${GREEN}===================================================$RESET"
echo -e "master-node=1\nmaster-node-public-ip=${ip_public}\nstorage-server-port=${ss_http}" >>/etc/beldex/beldex.conf
if [ "$beldexd_p2p" != 22022 ]; then
    echo "p2p-bind-port=$beldexd_p2p" >>/etc/beldex/beldex.conf
fi
if [ "$beldexd_rpc" != 22023 ]; then
    echo "rpc-bind-port=$beldexd_rpc" >>/etc/beldex/beldex.conf
fi
if [ "$beldexd_qnet" != 22025 ]; then
    echo "quorumnet-port=$beldexd_qnet" >>/etc/beldex/beldex.conf
fi


echo "${GREEN}Moving storage server data files to /var/lib/beldex/storage${RESET}"
echo "${GREEN}=========================================================${RESET}"
if ! [ -d /var/lib/beldex/storage ]; then
    mkdir -v /var/lib/beldex/storage
    chown -v _beldex:_beldex /var/lib/beldex/storage
fi
mv -vf "$ss_data"/{*.db,*.pem} /var/lib/beldex/storage
chown -v _beldex:_beldex /var/lib/beldex/storage/{*.db,*.pem}
echo "${GREEN}Replacing beldex-storage-server configuration in /etc/beldex/storage.conf${RESET}"
echo "${GREEN}=====================================================================${RESET}"
echo -e "ip=0.0.0.0\nport=$ss_http\nlmq-port=$ss_lmq\ndata-dir=/var/lib/beldex/storage" >/etc/beldex/storage.conf



echo "${GREEN}Moving belnet files to /var/lib/belnet/router${RESET}"
echo "${GREEN}===============================================${RESET}"
mv -vf "$belnet_data"/{*.private,*.signed,netdb,profiles.dat} /var/lib/belnet/router
chown -v _belnet:_beldex /var/lib/belnet/router/{*.private,*.signed,profiles.dat}
chown -R _belnet:_beldex /var/lib/belnet/router/netdb  # too much for -v
echo "${GREEN}Updating beldexd configuration in /etc/beldex/beldex.conf${RESET}"
echo "${GREEN}===================================================${RESET}"
if [ -n "$belnet_simple" ]; then
    perl -pi -e "
        if (/^\[beldexd/ ... /^\[/) {
            s/jsonrpc=127\.0\.0\.1:22023/jsonrpc=127.0.0.1:${beldexd_rpc}/;
        }
        if (/^\[bind/ ... /^\[/) {
            s/^#?[\w:.{}-]+=\d+/$belnet_ip=$belnet_port/;
        }" /etc/beldex/belnet-router.ini
else
    perl -pi -e "
        if (/^\[beldexd/ ... /^\[/) {
            s/jsonrpc=127\.0\.0\.1:22023/jsonrpc=127.0.0.1:${beldexd_rpc}/;
        }
        if (/^\[router\]/) {
            \$_ .= qq{public-ip=$belnet_ip\npublic-port=$belnet_port\n};
        }
        if (/^\[router/ ... /^\[/) {
            s/^public-(?:ip|port)=.*//;
        }

        if (/^\[bind/ ... /^\[/) {
            s/^#?[\w:.{}-]+=\d+/0.0.0.0=$belnet_port/;
        }" /etc/beldex/belnet-router.ini
fi


echo "${GREEN}Done moving/copying files.  Starting beldex services...${RESET}"
systemctl_verbose 'Unmasking services' \
    systemctl unmask beldex-node.service belnet-router.service beldex-storage-server.service
systemctl_verbose 'Enabling automatic startup of beldex services' \
    systemctl enable beldex-node.service belnet-router.service beldex-storage-server.service

# Try to start a few times because belnet deliberately dies (expecting to be restarted) if it can't
# reach beldexd on startup to get keys.
for ((i = 0; i < 10; i++)); do
    if systemctl start beldex-node.service belnet-router.service beldex-storage-server.service 2>/dev/null; then
        break
    fi
    sleep 1
done

for s in beldex-node belnet-router beldex-storage-server; do
    if ! systemctl is-active -q $s.service; then
        echo -e "${BYELLOW}$s.service failed to start.${RESET} Check its status using the commands below.\n"
    fi
done

echo "${GREEN}Migration complete!${RESET}

You can check on and control your service using these commands:

    # Show general status of the process:
    sudo systemctl status beldex-node
    sudo systemctl status beldex-storage-server
    sudo systemctl status belnet-router

    # Start/stop/restart a service:
    sudo systemctl start beldex-node
    sudo systemctl restart beldex-node
    sudo systemctl stop beldex-node

    # Query beldexd for status (does not need sudo)
    beldexd status

    # Show the last 100 lines of logs of a service:
    sudo journalctl -au beldex-node -n 100

    # Continually watch the logs of a service (Ctrl-C to quit):
    sudo journalctl -au beldex-node -f

"
