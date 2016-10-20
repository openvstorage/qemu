#!/bin/bash

SRCDIR="$1"

set -eux

if [ $# -ne 1 ]
then
  echo "Usage: $0 <debianized_source_dir>"
  exit 1
fi

if [ ! -d "${SRCDIR}" ]
then
  echo "Sourcedir ${SRCDIR} not found?! Aborting build..."
  exit 1
fi

set -e

# the OVS apt repo hosts dependencies that are not yet available in Ubuntu
echo "deb http://apt.openvstorage.com unstable main" | sudo tee /etc/apt/sources.list.d/ovsaptrepo.list

echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections

# apt-get update is needed to fetch info on updated packages since the docker image was built
echo ">>> APT-GET UPDATE <<<"
sudo apt-get -qq update

## we know we depend on the libovsvolumedriver-dev package, and we want latest greatest, so install from artifact

for p in libovsvolumedriver_*_amd64.deb libovsvolumedriver-dev_*_amd64.deb
do
  echo -n "Installing $p..."
  sudo dpkg -i $p || sudo apt-get install --allow-unauthenticated -qq -y -f
  [ $? -ne 0 ] && echo 'FAILED' || echo 'OK'
done

## fetch newer seabios package; qemu depends on it so we need to provide it as well
wget -nc http://archive.ubuntu.com/ubuntu/pool/main/s/seabios/seabios_1.8.2-1ubuntu1_all.deb

cd ${SRCDIR}

echo ">>> INSTALLING BUILD DEPENDENCIES <<<"
sudo apt-get install -y libgnutls-dev
sudo apt-get install -y $(dpkg-checkbuilddeps 2>&1 | sed -e 's/.*dependencies://' -e 's/ ([^)]*)/ /g')

echo ">>> BUILDING DEBIAN PACKAGES <<<"
dpkg-buildpackage -us -uc -b

## .deb && *.ddeb packages should be available now
