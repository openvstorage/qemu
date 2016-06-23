#!/bin/bash

set -e

sudo yum install -y centos-release-qemu-ev
sudo yum install -y gcc gcc-c++ make cmake

echo '[openvstorage]
name=Open vStorage repo
baseurl=http://yum.openvstorage.org/CentOS/7/x86_64/dists/unstable
enabled=1
gpgcheck=0' | sudo tee /etc/yum.repos.d/openvstorage.repo

## install the libovsvolumedriver*.rpm files copied in by jenkins
sudo yum install -y libovsvolumedriver*.rpm

## prepare the build env
chown -R jenkins:jenkins qemu
cd qemu/rpm
mkdir -p ./{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo "%_topdir ${PWD}" > ~/.rpmmacros

echo '>>> FETCHING UPSTREAM SOURCES <<<' 
spectool -g -R SPECS/qemu-kvm.spec

if [ ! -d kvm-unit-tests ]
then
   git clone https://git.kernel.org/pub/scm/virt/kvm/kvm-unit-tests.git
   cd kvm-unit-tests
   git checkout 4ea7633
   cd ..
   tar cjf SOURCES/kvm-unit-tests.git-4ea7633.tar.bz2 --exclude-vcs kvm-unit-tests
fi

#################################################################################################################
## HACK: there's a zillion of patches in the CentOS qemu specfile; these don't apply on our sources on github
##       but fortunately our changes can still be applied onto the CentOS patched sources. So we fetch our sources
##       in patch format from github (changes between upstream and our master branch) and we'll apply these on top 
##       of the CentOS patched pristine source. Our specfile has the logic to do this (note: uses git apply 
##       instead of the patch utility due to binary contents) so we only fetch the patch here...
#################################################################################################################

echo '>>> GET OPENVSTORAGE PATCH FROM GITHUB <<<'
rm -f SOURCES/openvstorage.patch
wget -q -nc -O SOURCES/openvstorage.patch https://github.com/openvstorage/qemu/compare/upstream...master.patch

echo '>>> INSTALL BUILD DEPENDENCIES <<<'
sudo yum install -y $(rpmbuild -ba SPECS/qemu-kvm.spec 2>&1 | awk '/is needed/ { print $1 }')

echo '>>> BUILD RPMS <<<'
rpmbuild -ba SPECS/qemu-kvm.spec

