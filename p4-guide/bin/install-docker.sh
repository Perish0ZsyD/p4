#! /bin/bash

# Use the test environment install script provided with Docker to install it.
# We can use a different method to install Docker later if we decide we
# want more control of the options.

# I found these steps described here:
# https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-using-the-convenience-script

linux_version_warning() {
    1>&2 echo "Found ID ${ID} and VERSION_ID ${VERSION_ID} in /etc/os-release"
    1>&2 echo "This script has only been tested on these combinations:"
    1>&2 echo "    ID ubuntu, VERSION_ID in 20.04 22.04 23.04"
    1>&2 echo "    ID fedora, VERSION_ID in 36 37 38"
    1>&2 echo "    ID rocky, VERSION_ID in 9.2"
    1>&2 echo ""
    1>&2 echo "Proceed installing manually at your own risk of"
    1>&2 echo "significant time spent figuring out how to make it all"
    1>&2 echo "work, or consider getting VirtualBox and creating an"
    1>&2 echo "Ubuntu virtual machine with one of the tested versions."
}

if [ ! -r /etc/os-release ]
then
    1>&2 echo "No file /etc/os-release.  Cannot determine what OS this is."
    linux_version_warning
    exit 1
fi
source /etc/os-release

supported_distribution=0
if [ "${ID}" = "ubuntu" ]
then
    case "${VERSION_ID}" in
	20.04)
	    supported_distribution=1
	    ;;
	22.04)
	    supported_distribution=1
	    ;;
	23.04)
	    supported_distribution=1
	    ;;
    esac
elif [ "${ID}" = "fedora" ]
then
    case "${VERSION_ID}" in
	# I tried running this script on a Fedora 35 system on
	# 2023-Jul-16, but the get-docker.sh script that is downloaded
	# and run below says that Fedora 35 is no longer supported, and
	# in my testing it no longer worked correctly.
	36)
	    supported_distribution=1
	    ;;
	37)
	    supported_distribution=1
	    ;;
	38)
	    supported_distribution=1
	    ;;
    esac
elif [ "${ID}" = "rocky" ]
then
    case "${VERSION_ID}" in
	9.2)
	    supported_distribution=1
	    ;;
    esac
fi

if [ ${supported_distribution} -eq 1 ]
then
    echo "Found supported ID ${ID} and VERSION_ID ${VERSION_ID} in /etc/os-release"
else
    linux_version_warning
    exit 1
fi

echo "Disk space before installing docker"
date
df -BM .

set -x
if [ "${ID}" == "ubuntu" ]
then
    sudo apt-get --yes install curl
elif [ "${ID}" = "fedora" ]
then
    sudo dnf -y install curl
fi

if [ "${ID}" == "ubuntu" -o "${ID}" == "fedora" ]
then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
elif [ "${ID}" == "rocky" ]
then
    # Steps for Rocky Linux are based on published instructions on
    # docker.com for CentOS:
    # https://docs.docker.com/engine/install/centos/
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    # Linux post-install steps
    sudo groupadd docker
    sudo usermod -aG docker $USER
fi

# Enable docker service to start automatically when the system is booted:
# https://docs.docker.com/engine/install/linux-postinstall/#configure-docker-to-start-on-boot-with-systemd
if [ "${ID}" = "fedora" -o "${ID}" = "rocky" ]
then
    sudo systemctl enable docker.service
    sudo systemctl enable containerd.service
fi
set +x

echo "Disk space after installing docker"
date
df -BM .

echo ""
echo ""
echo "If you want all terminal windows to be able to run docker"
echo "commands without using 'sudo', reboot the system."
echo ""
echo "If you would like to try a quick test of this docker"
echo "installation (after rebooting), try the following command:"
echo ""
echo "    docker run hello-world"
