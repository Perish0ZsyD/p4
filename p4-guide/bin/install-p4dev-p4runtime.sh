#! /bin/bash

# Copyright 2018-present Cisco Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This script differs from install-p4dev.sh as follows:

# install-p4dev.sh executes steps to build the behavioral-model
# simple_switch program, using only Thrift as the IPC mechanism for
# other processes to connect to it and make table add/modify/delete
# requests.

# install-p4dev-p4runtime.sh executes steps to build the
# behavioral-model simple_switch_grpc program, which uses the
# P4Runtime API as the IPC mechanism for other processes to connect to
# it and make table add/modify/delete requests.  It is built with the
# necessary options so that the simple_switch_grpc process _also_
# supports Thrift, but this is only intended as a debugging aid,
# e.g. to show table contents using the simple_switch_CLI program.

# Size of the largest 3 source trees, after being built on an x86_64
# machine, without documentation:
# grpc - 0.7G
# p4c - 1.4G
# behavioral-model - 2.5G

set -e

# The maximum number of gcc/g++ jobs to run in parallel.  1 is the
# safest number that enables compiling p4c even on machines with only
# 2 GB of RAM, and even on machines with significantly more RAM, it
# does not speed things up a lot to run multiple jobs in parallel.
MAX_PARALLEL_JOBS=1

# Remember the current directory when the script was started:
INSTALL_DIR="${PWD}"

THIS_SCRIPT_FILE_MAYBE_RELATIVE="$0"
THIS_SCRIPT_DIR_MAYBE_RELATIVE="${THIS_SCRIPT_FILE_MAYBE_RELATIVE%/*}"
THIS_SCRIPT_DIR_ABSOLUTE=`readlink -f "${THIS_SCRIPT_DIR_MAYBE_RELATIVE}"`

ubuntu_release=`lsb_release -s -r`

echo "This script builds and installs the P4_16 (and also P4_14)"
echo "compiler, and the behavioral-model software packet forwarding"
echo "program, that can behave as just about any legal P4 program."
echo ""
echo "It regularly tested on freshly installed Ubuntu 16.04 and Ubuntu"
echo "18.04 systems, with all Ubuntu software updates as of the date"
echo "of testing.  See this directory for log files recording the last"
echo "date this script was tested on its supported operating systems:"
echo ""
echo "    https://github.com/jafingerhut/p4-guide/tree/master/bin/output"
echo ""
echo "The files installed by this script consume about 8.5 GB of disk space."
echo ""
echo "On a 2015 MacBook Pro with a decent speed Internet connection"
echo "and an SSD drive, running Ubuntu Linux in a VirtualBox VM, it"
echo "took about 60 to 70 minutes."
echo ""
echo "Versions of software that will be installed by this script:"
echo ""
echo "+ protobuf: github.com/google/protobuf v3.2.0"
echo "+ gRPC: github.com/google/grpc.git v1.3.2, with patches for Ubuntu 18.04"
echo "+ PI: github.com/p4lang/PI latest version"
echo "+ behavioral-model: github.com/p4lang/behavioral-model latest version"
echo "  which, as of 2019-Jun-10, also installs these things:"
echo "  + thrift version 0.9.2"
echo "  + nanomsg version 1.0.0"
echo "  + nnpy git checkout c7e718a5173447c85182dc45f99e2abcf9cd4065 (latest as of 2015-Apr-22"
echo "+ p4c: github.com/p4lang/p4c latest version"
echo "+ Mininet: github.com/mininet/mininet latest version"
echo "+ Python packages: grpcio 1.8.1, protobuf 3.11.2"
echo "+ Python packages: crcmod, latest version"
echo ""
echo "Note that anything installed as 'the latest version' can change"
echo "its precise contents from one run of this script to another."
echo "That is an intentional property of this script -- to get the"
echo "latest version of that software.  If you want particular"
echo "versions that are not the latest, you can modify this script by"
echo "adding 'git checkout <tag>' and/or 'git checkout <commit-sha>'"
echo "command at the appropriate places."
echo ""

# TBD: Consider adding a check for how much free disk space there is
# and giving a message about it and aborting if it is too low.  On
# Ubuntu 16.04, at least, the command `df --output=avail .` shows how
# many Kbytes are free on the file system containing the directory
# `.`, which could be interpreted in a bash script without having to
# parse so much output from a different command like `df -h .`


REPO_CACHE_DIR="${INSTALL_DIR}/repository-cache"
get_from_nearest() {
    local git_url="$1"
    local repo_cache_name="$2"

    if [ -e "${REPO_CACHE_DIR}/${repo_cache_name}" ]
    then
	echo "Creating contents of ${git_url} from local cached copy ${REPO_CACHE_DIR}/${repo_cache_name}"
	tar xkzf "${REPO_CACHE_DIR}/${repo_cache_name}"
    else
	echo "git clone ${git_url}"
	git clone "${git_url}"
    fi
}


echo "------------------------------------------------------------"
echo "Time and disk space used before installation begins:"
date
df -h .
df -BM .

# Install a few packages (vim is not strictly necessary -- installed for
# my own convenience):
sudo apt-get --yes install git vim

# Run a child process in the background that will keep sudo
# credentials fresh.  The hope is that after a user enters their
# password once, they will not need to do so again for the entire
# duration of running this install script.

# However, since it runs in the background, do _not_ start it until
# after the first command in this script that uses 'sudo', so the
# foreground 'sudo' command will cause the password prompt to be
# waited for, if it is needed.
"${THIS_SCRIPT_DIR_ABSOLUTE}/keep-sudo-credentials-fresh.sh" &
CHILD_PROCESS_PID=$!

clean_up() {
    echo "Killing child process"
    kill ${CHILD_PROCESS_PID}
    # Invalidate the user's cached credentials
    sudo --reset-timestamp
    exit
}

# Kill the child process
trap clean_up SIGHUP SIGINT SIGTERM

# Install Python2.  This is required for p4c, but there are several
# earlier packages that check for python in their configure scripts,
# and on a minimal Ubuntu 18.04 Desktop Linux system they find
# Python3, not Python2, unless we install Python2.  Most Python code
# in open source P4 projects is written for Python2.
sudo apt-get --yes install python

# Install Ubuntu packages needed by protobuf v3.2.0, from its src/README.md
sudo apt-get --yes install autoconf automake libtool curl make g++ unzip
# zlib is not required to install protobuf, nor do I think it is
# required by the open source P4 tools for protobuf to be built with
# support for zlib, but it seems like a reasonable thing to enable.
sudo apt-get --yes install zlib1g-dev

# Install pkg-config here, as it is required for p4lang/PI
# installation to succeed.
sudo apt-get --yes install pkg-config

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-1-before-protobuf.txt

echo "------------------------------------------------------------"
echo "Installing Google protobuf, needed for p4lang/p4c and for p4lang/behavioral-model simple_switch_grpc"
echo "start install protobuf:"
date

cd "${INSTALL_DIR}"
get_from_nearest https://github.com/google/protobuf protobuf.tar.gz
cd protobuf
git checkout v3.2.0
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
# Save about 0.5G of storage by cleaning up protobuf build
make clean

echo "end install protobuf:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-2-after-protobuf.txt

echo "------------------------------------------------------------"
echo "Installing grpc, needed for installing p4lang/PI"
echo "start install grpc:"
date

# From BUILDING.md of grpc source repository
sudo apt-get --yes install build-essential autoconf libtool pkg-config

get_from_nearest https://github.com/google/grpc.git grpc.tar.gz
cd grpc
# This version works fine with Ubuntu 16.04
git checkout tags/v1.3.2
if [[ "${ubuntu_release}" > "18" ]]
then
    # Apply patches that seem to be necessary in order for grpc v1.3.2
    # to compile and install successfully on an Ubuntu 18.04 system
    PATCH_DIR="${THIS_SCRIPT_DIR_ABSOLUTE}/grpc-v1.3.2-patches-for-ubuntu18.04"

    # I have tried with the openssl-1.1.0.diff patch applied, in addition
    # to the others, but it leads to errors when building grpc on an Ubuntu
    # 18.04.1 system, because of not being able to find the definition of
    # a function RSA_set0_key.  Leave that patch out for now, since things
    # seem to build better without it.
    #for PATCH_FILE in openssl-1.1.0.diff no-werror.diff unvendor-zlib.diff fix-libgrpc++-soname.diff make-pkg-config-files-nonexecutable.diff add-wrap-memcpy-flags.diff

    for PATCH_FILE in no-werror.diff unvendor-zlib.diff fix-libgrpc++-soname.diff make-pkg-config-files-nonexecutable.diff add-wrap-memcpy-flags.diff
    do
        patch -p1 < "${PATCH_DIR}/${PATCH_FILE}"
    done
fi
git submodule update --init --recursive
make
sudo make install
sudo ldconfig
# Save about 0.1G of storage by cleaning up grpc v1.3.2 build
make clean

echo "end install grpc:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-3-after-grpc.txt

echo "------------------------------------------------------------"
echo "Installing p4lang/PI, needed for installing p4lang/behavioral-model simple_switch_grpc"
echo "start install PI:"
date

# Deps needed to build PI:
sudo apt-get --yes install libjudy-dev libreadline-dev valgrind libtool-bin libboost-dev libboost-system-dev libboost-thread-dev

git clone https://github.com/p4lang/PI
cd PI
git submodule update --init --recursive
git log -n 1
./autogen.sh
./configure --with-proto --without-internal-rpc --without-cli --without-bmv2
# Output I saw:
#Features recap ......................................
#Use sysrepo gNMI implementation .............. : no
#Compile demo_grpc ............................ : no
#
#Features recap ......................................
#Compile for bmv2 ............................. : no
#Compile C++ frontend ......................... : yes
#Compile p4runtime.proto and associated fe .... : yes
#Compile internal RPC ......................... : no
#Compile PI C CLI ............................. : no
make
sudo make install

# Save about 0.25G of storage by cleaning up PI build
make clean

echo "end install PI:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-4-after-PI.txt

echo "------------------------------------------------------------"
echo "Installing p4lang/behavioral-model"
echo "start install behavioral-model:"
date

# Following instructions in the file
# targets/simple_switch_grpc/README.md in the p4lang/behavioral-model
# repository with git commit 66cefc5e901eafcebb0e1a8f681a05795463215a.
# That README.md file was last updated 2018-Apr-03.

# It says to first follow the instructions here:
# https://github.com/p4lang/PI#dependencies to install required
# dependencies for the `--with-proto` configure flag.  This script
# does _not_ use the option `--with-sysrepo` configure flag, which is
# needed for experimental gNMI support.  That should all have been
# done by this time, by the script above.

get_from_nearest https://github.com/p4lang/behavioral-model.git behavioral-model.tar.gz
cd behavioral-model
# Get latest updates that are not in the repo cache version
git pull
git log -n 1
# This command installs Thrift, which I want to include in my build of
# simple_switch_grpc
./install_deps.sh
# simple_switch_grpc README.md says to configure and build the bmv2
# code first, using these commands:
./autogen.sh
# Remove 'CXXFLAGS ...' part to disable debug
./configure --with-pi 'CXXFLAGS=-O0 -g'
make
sudo make install
# Now build simple_switch_grpc
cd targets/simple_switch_grpc
./autogen.sh
# Remove 'CXXFLAGS ...' part to disable debug
./configure --with-thrift 'CXXFLAGS=-O0 -g'
# I saw the following near end of output of 'configure' command:
#Features recap ......................
#With Sysrepo .................. : no
#With Thrift ................... : yes
make
sudo make install
sudo ldconfig

echo "end install behavioral-model:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-5-after-behavioral-model.txt

echo "------------------------------------------------------------"
echo "Installing p4lang/p4c"
echo "start install p4c:"
date

# Install Ubuntu dependencies needed by p4c, from its README.md
# Matches latest p4c README.md instructions as of 2019-Oct-09
sudo apt-get --yes install cmake g++ git automake libtool libgc-dev bison flex libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev libboost-graph-dev llvm pkg-config python python-scapy python-ipaddr python-ply python3-pip tcpdump

pip --version
pip3 --version
# At multiple points I do a 'pip list' command.  This is not required
# for a successful installation -- I do it mainly because I am curious
# to see in the log output files from running this script what
# packages and versions were installed at those times during script
# execution.
set -x
pip list
pip3 list
set +x

# Starting in 2019-Nov, Python3 version of Scapy is needed for `cd
# p4c/build ; make check` to succeed.
pip3 install scapy
set -x
pip3 list
set +x

# Clone p4c and its submodules:
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
git log -n 1
mkdir build
cd build
# Configure for a debug build
cmake .. -DCMAKE_BUILD_TYPE=DEBUG $*
make -j${MAX_PARALLEL_JOBS}
sudo make install
sudo ldconfig

echo "end install p4c:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-6-after-p4c.txt

echo "------------------------------------------------------------"

echo "Installing Mininet - not necessary to run P4 programs, but useful if"
echo "you want to run tutorials from https://github.com/p4lang/tutorials"
echo "repository."
echo "start install mininet:"
date

git clone https://github.com/mininet/mininet mininet
sudo ./mininet/util/install.sh -nwv

echo "end install mininet:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-7-after-mininet-install.txt

echo "------------------------------------------------------------"
echo "Installing a few miscellaneous packages"
echo "start install miscellaneous packages:"
date

# grpcio 1.3.2 would match the version of gRPC that we have installed.
# At least on 2020-Jan-21 when I tried to install that version of
# grpcio using pip, it indicated that many other versions were
# available, but not that one.  The closest two versions were 1.3.0
# and 1.3.3.

# I tried 1.3.3, but then the p4lang/tutorials basic exercise 'make
# run' failed with an error message that mentioned a grpc Python
# library class UnaryUnaryClientInterceptor not being found.  That
# string is mentioned in grpcio 1.17.1, but not 1.3.3.

# The earliest grpcio package version I found that mentions this class
# is 1.8.1.

# So far, version TBD has worked well when doing _basic_ P4Runtime API
# testing on a system on which this install script was run.
sudo pip install grpcio==1.8.1
set -x
pip list
set +x

# When installing grpcio 1.8.1, it installs protobuf 3.11.2
# automatically as a dependency.  Later trying to 'pip install
# protobuf==3.2.0' leaves it at the newer version 3.11.2, so do not
# bother running the next commented command.
#sudo pip install protobuf==3.2.0

# Things needed for `cd tutorials/exercises/basic ; make run` to work:
sudo apt-get --yes install python-psutil libgflags-dev net-tools
sudo pip install crcmod
set -x
pip list
set +x

echo "end install miscellaneous packages:"
date

cd "${INSTALL_DIR}"
find /usr/lib /usr/local $HOME/.local | sort > usr-local-8-after-miscellaneous-install.txt

set -x
pip list
pip3 list
set +x

set +e

echo "------------------------------------------------------------"
echo "Time and disk space used when installation was complete:"
date
df -h .
df -BM .

cd "${INSTALL_DIR}"
DETS="install-details"
mkdir -p "${DETS}"
mv usr-local-*.txt "${DETS}"
cd "${DETS}"
diff usr-local-1-before-protobuf.txt usr-local-2-after-protobuf.txt > usr-local-file-changes-protobuf.txt
diff usr-local-2-after-protobuf.txt usr-local-3-after-grpc.txt > usr-local-file-changes-grpc.txt
diff usr-local-3-after-grpc.txt usr-local-4-after-PI.txt > usr-local-file-changes-PI.txt
diff usr-local-4-after-PI.txt usr-local-5-after-behavioral-model.txt > usr-local-file-changes-behavioral-model.txt
diff usr-local-5-after-behavioral-model.txt usr-local-6-after-p4c.txt > usr-local-file-changes-p4c.txt
diff usr-local-6-after-p4c.txt usr-local-7-after-mininet-install.txt > usr-local-file-changes-mininet-install.txt
diff usr-local-7-after-mininet-install.txt usr-local-8-after-miscellaneous-install.txt > usr-local-file-changes-miscellaneous-install.txt

P4GUIDE_BIN="${THIS_SCRIPT_DIR_ABSOLUTE}"

echo "----------------------------------------------------------------------"
echo "Output of script p4-environment-info.sh"
echo "----------------------------------------------------------------------"
"${THIS_SCRIPT_DIR_ABSOLUTE}/p4-environment-info.sh"
echo "----------------------------------------------------------------------"

echo "----------------------------------------------------------------------"
echo "CONSIDER READING WHAT IS BELOW"
echo "----------------------------------------------------------------------"
echo ""

cd "${INSTALL_DIR}"
echo "P4_INSTALL=\"${INSTALL_DIR}\"" > p4setup.bash
echo "BMV2=\"\$P4_INSTALL/behavioral-model\"" >> p4setup.bash
echo "P4GUIDE_BIN=\"${P4GUIDE_BIN}\"" >> p4setup.bash
echo "export PATH=\"\$P4GUIDE_BIN:\$BMV2/tools:/usr/local/bin:\$PATH\"" >> p4setup.bash

echo "set P4_INSTALL=\"${INSTALL_DIR}\"" > p4setup.csh
echo "set BMV2=\"\$P4_INSTALL/behavioral-model\"" >> p4setup.csh
echo "set P4GUIDE_BIN=\"${P4GUIDE_BIN}\"" >> p4setup.csh
echo "set path = ( \$P4GUIDE_BIN \$BMV2/tools /usr/local/bin \$path )" >> p4setup.csh

echo ""
echo "Created files: p4setup.bash p4setup.csh"
echo ""
echo "If you use a Bash-like command shell, you may wish to copy the lines"
echo "of the file p4setup.bash to your .bashrc or .profile files in your"
echo "home directory to add some useful commands to your"
echo "command path every time you log in or create a new shell."
echo ""
echo "If you use the tcsh or csh shells, instead copy the contents of the"
echo "file p4setup.csh to your .tcshrc or .cshrc file in your home"
echo "directory."

echo "----------------------------------------------------------------------"
echo "CONSIDER READING WHAT IS ABOVE"
echo "----------------------------------------------------------------------"

clean_up
