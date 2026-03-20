#!/bin/bash

# Retrieve a PCAP file from a VM 
function retrieve_pcap_file {
    local vm_name="$1"
    local private_ip="$2"
    local port="${3:-}"
    local remote_file="$4"
    local local_dir="$5"
    local pcap_file_name="$6"

    echo "Retrieving $pcap_file_name from $vm_name ($private_ip)..."

    mkdir -p "$local_dir"
    local dst="${local_dir}/${vm_name}_${pcap_file_name}"

    if [ -n "$port" ] && [ "$port" != "22" ]; then
        if scp -P "$port" root@"$private_ip":"$remote_file" "$dst" 2>/dev/null; then
            echo "Copied via scp to $dst"
            return 0
        else
            echo "scp (with -P $port) failed; will try sftp fallback..."
        fi
    else
        if scp root@"$private_ip":"$remote_file" "$dst" 2>/dev/null; then
            echo "Copied via scp to $dst"
            return 0
        else
            echo "scp (default port) failed; will try sftp fallback..."
        fi
    fi

    if [ -n "$port" ] && [ "$port" != "22" ]; then
        sftp -P "$port" root@"$private_ip" <<EOF
get "$remote_file" "$dst"
bye
EOF
    else
        sftp root@"$private_ip" <<EOF
get "$remote_file" "$dst"
bye
EOF
    fi

    if [ -f "$dst" ]; then
        echo "File retrieved successfully and stored at $dst"
        return 0
    else
        echo "Failed to retrieve $remote_file from $private_ip"
        return 1
    fi
}
echo "1) Run a new simulation"
echo "2) Analyze previously saved PCAPs"
echo "3) Exit"
while true; do
    read -p "Enter 1, 2 or 3: " MAIN_OPTION

    case "$MAIN_OPTION" in
        1) echo "Starting simulation setup..."
           break ;;
        2) python3 SIEM.py
           exit 0 ;;     
        3) echo "Exiting."
           exit 0 ;;  
        *)echo "Invalid choice. Please enter 1, 2 or 3." ;;  
    esac
done

# Clear existing Ansible hosts file
sudo rm -f /etc/ansible/hosts

VM_ATTACKER=attacker
VM_VICTIM=victim
MASTER_IP=$(hostname -I | awk '{print $1}' | tr -d ' ')
CENDPOINT=https://grid5.mif.vu.lt/cloud3/RPC2

echo "Master machine IP: $MASTER_IP"

# setup credentials and simulation choice
read -p 'Please enter username for your VU MIF cloud infrastructure: ' CUSER
read -sp 'Please enter password for your VU MIF cloud infrastructure: ' CPASSWORD
echo

echo "Choose offense (attack) simulation to run:"
echo "  1) Large number of TCP connections to external internet resource"
echo "  2) Brute force attempt via SSH"
echo "  3) Malicious object detected but not deleted"
read -p "Enter 1, 2 or 3: " SIM_CHOICE

case "$SIM_CHOICE" in
    1) SIM_IDX=1; SIM_LABEL="tcp" ;;
    2) SIM_IDX=2; SIM_LABEL="ssh" ;;
    3) SIM_IDX=3; SIM_LABEL="file" ;;
    *) echo "Invalid choice. Defaulting to 1"; SIM_IDX=1; SIM_LABEL="tcp" ;;
esac

VM_VICTIM_YML="V${SIM_IDX}.yml"
VM_ATTACKER_YML="A${SIM_IDX}.yml"

echo "Selected simulation $SIM_IDX -> Victim playbook: $VM_VICTIM_YML  Attacker playbook: $VM_ATTACKER_YML"

if [ -z "$CUSER" ]; then
    echo "No username provided. Skipping VM creation."
    VM_NOT_CREATED=false
else
    VM_NOT_CREATED=true
fi

echo "Making VM on user $CUSER"

eval $(ssh-agent)
if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519
fi
ssh-add

if $VM_NOT_CREATED; then
    echo "Creating $VM_ATTACKER-vm..."
    VM_ATTACKER_VM_REZ=$(onetemplate instantiate "debian12" --name "$VM_ATTACKER" --net_context --ssh ~/.ssh/id_ed25519.pub --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    if [ $? -ne 0 ]; then
        echo "Error: VM creation failed with error: $VM_ATTACKER_VM_REZ"
        exit 1
    fi

    ATTACKER_VM_ID=$(echo $VM_ATTACKER_VM_REZ | cut -d ' ' -f 3)
    echo "$VM_ATTACKER VM ID: $ATTACKER_VM_ID"

    echo "Creating $VM_VICTIM-vm..."
    VM_VICTIM_VM_REZ=$(onetemplate instantiate "debian12" --name "$VM_VICTIM" --net_context --ssh ~/.ssh/id_ed25519.pub --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    if [ $? -ne 0 ]; then
        echo "Error: VM creation failed with error: $VM_VICTIM_VM_REZ"
        exit 1
    fi

    VICTIM_VM_ID=$(echo $VM_VICTIM_VM_REZ | cut -d ' ' -f 3)
    echo "$VM_VICTIM VM ID: $VICTIM_VM_ID"

    echo "Waiting for VM to RUN 45 sec."
    sleep 45

    echo "Adding newly created machine's IP address to Ansible hosts file"
    if [ ! -d /etc/ansible/ ]; then
        sudo mkdir -p /etc/ansible/
    fi

    # Get attacker VM details
    ATTACKER_VM_DETAILS=$(onevm show $ATTACKER_VM_ID --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)
    CSSH_PRIP_ATTACKER=$(echo "$ATTACKER_VM_DETAILS" | grep "PRIVATE_IP" | cut -d '=' -f 2 | tr -d '"')
    echo -e "\n[$VM_ATTACKER]\n$CSSH_PRIP_ATTACKER" | sudo tee -a /etc/ansible/hosts
    ssh-keyscan -H $CSSH_PRIP_ATTACKER >> ~/.ssh/known_hosts

    # Get victim VM details
    VICTIM_VM_DETAILS=$(onevm show $VICTIM_VM_ID --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)
    CSSH_PRIP_VICTIM=$(echo "$VICTIM_VM_DETAILS" | grep "PRIVATE_IP" | cut -d '=' -f 2 | tr -d '"')
    echo -e "\n[$VM_VICTIM]\n$CSSH_PRIP_VICTIM" | sudo tee -a /etc/ansible/hosts
    ssh-keyscan -H $CSSH_PRIP_VICTIM >> ~/.ssh/known_hosts
fi

# Run Ansible playbooks based on simulation choice
if [ "$SIM_IDX" -eq 2 ]; then
    echo "Running victim playbook first..."
    ansible-playbook "$VM_VICTIM_YML" --user root -e "attacker_ip=$CSSH_PRIP_ATTACKER"
    ansible-playbook "$VM_ATTACKER_YML" --user root -e "target_ip=$CSSH_PRIP_VICTIM"
else
    echo "Running attacker playbook first..."
    ansible-playbook "$VM_ATTACKER_YML" --user root -e "target_ip=$CSSH_PRIP_VICTIM"
    ansible-playbook "$VM_VICTIM_YML" --user root -e "attacker_ip=$CSSH_PRIP_ATTACKER master_ip=$MASTER_IP"
fi

# Store PCAP files from both VMs
LOCAL_DIR="$HOME/Downloads/master"
mkdir -p "$LOCAL_DIR"

REMOTE_PCAP_ATTACKER="/home/captureA_${SIM_LABEL}.pcap"
REMOTE_PCAP_VICTIM="/home/captureB_${SIM_LABEL}.pcap"

retrieve_pcap_file "$VM_ATTACKER" "$CSSH_PRIP_ATTACKER" "" "$REMOTE_PCAP_ATTACKER" "$LOCAL_DIR" "captureA_${SIM_LABEL}.pcap"
retrieve_pcap_file "$VM_VICTIM" "$CSSH_PRIP_VICTIM" "" "$REMOTE_PCAP_VICTIM" "$LOCAL_DIR" "captureB_${SIM_LABEL}.pcap"

echo "Done. If present, PCAPs saved to ${LOCAL_DIR}:"
echo "  ${LOCAL_DIR}/${VM_ATTACKER}_captureA_${SIM_LABEL}.pcap"
echo "  ${LOCAL_DIR}/${VM_VICTIM}_captureB_${SIM_LABEL}.pcap"
echo
# Analyze PCAPs prompt
read -p "Do you want to analyze the PCAPs now? (y/n): " ANALYZE_CHOICE

if [[ "$ANALYZE_CHOICE" =~ ^[Yy]$ ]]; then
    python3 SIEM.py
else
    echo "Exiting."
fi

exit 0
