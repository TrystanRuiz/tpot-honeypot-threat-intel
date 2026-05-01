# Installation Steps

Orignal Video I followed - Video = https://youtu.be/uSohtNwQXuI?si=PXeezLlMXO5dqjA1 (they explain it better)

### 1. Create the VM in Proxmox

Creating a new Ubuntu VM (ID 100) on pve2 using a cloud image. 2 cores, 2GB RAM, 32GB disk with cloud-init for automated provisioning.

![Create VM](../screenshots/installation/01-create-vm.png)

### 2. Ubuntu cloud-init provisioning

Ubuntu installing automatically via cloud-init (curtin). The cloud image handles OS setup without a manual installer.

![Ubuntu Install](../screenshots/installation/02-ubuntu-install.png)

### 3. Fresh shell on the honeypot VM

Logged in as `cowrie@cowrie-honeypot` on VM 100. Fresh Ubuntu system ready for Cowrie installation.

![Fresh Shell](../screenshots/installation/03-fresh-shell.png)

### 4. Clone the Cowrie repository

Creating a directory and cloning the official Cowrie repo from GitHub.

![Clone Cowrie](../screenshots/installation/04-clone-cowrie.png)

### 5. Set up the Python virtual environment

Creating and activating a Python virtual environment for Cowrie's dependencies.

![Python Venv](../screenshots/installation/05-python-venv.png)

### 6. Configure iptables port redirect

Setting up an iptables NAT PREROUTING rule to redirect incoming SSH traffic on port 22 to Cowrie's listening port 2222. This makes the honeypot transparent to attackers.

![iptables Redirect](../screenshots/installation/06-iptables-redirect.png)

### 7. Verify iptables rules

Confirming the NAT PREROUTING rules are active with `sudo iptables-save`. The redirect from port 22 to 2222 is in place.

![iptables Save](../screenshots/installation/07-iptables-save.png)

### 8. Start Cowrie

Starting the Cowrie honeypot. TripleDES deprecation warnings are expected and non-breaking.

![Cowrie Start](../screenshots/installation/08-cowrie-start.png)

### 9. Cowrie listening for SSH connections

Cowrie is running and listening on port 2222. The log confirms `CowrieSSHFactory starting on 2222` and `Ready to accept SSH connections`.

![Cowrie Listening](../screenshots/installation/09-cowrie-listening.png)
