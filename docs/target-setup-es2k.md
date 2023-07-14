# Target Setup for Intel IPU ES2K

## Set Up Hardware Board
Hardware setup requires the Intel IPU device to be connected to a link partner
in a back-to-back manner. Refer to the setup topology in the
FXP_P4_SDE_User_Guide.md included in the documentation in official CI release
for details. This document also provides instructions on how to configure the
machine with required BIOS settings, required third-party software, boot
instructions, and system settings, as well as other information.

Follow the SDE User Guide with all the steps until ipumgmtd is started.

Perform following steps before starting ipumgmtd.

### Copy Custom Package to IMC
  Copy k8s_dp-0.9.pkg to IMC from the link partner machine and create a soft link.
  ```bash
  scp k8s_dp-0.9.pkg 100.0.0.100:/etc/dpcp/package
  ```
  On IMC:
  ```bash
  cd /etc/dpcp/package
  rm default_pkg.pkg
  ln -s k8s_dp-0.9.pkg default_pkg.pkg
  ```

### Enable CDQ Interface Creation
  Edit the config file (/etc/dpcp/cfg/cp_init.cfg) on IMC to enable CDQ.
  For details on this file and the specific edits required, refer to the
  FXP P4 SDE User Guide document.

### Run ipumgmtd
  Run ipumgmtd and check the status of ports
  ```bash
  /etc/init.d/run_default_init_app
  ifconfig lo up
  /usr/bin/cli_client -q -c -V
  ```

## Set up Host
Follow the steps listed in the FXP P4 SDE User Guide document, "Running from
HOST" section. The steps include configuring Linux kernel boot parameters to
enable IOMMU, ATE, etc.; installing ATE kernel and other RPMs; installing
required third-party software; installing p4sde and p4-cp-nws; loading drivers
and binding them to the device; configuring HugePages; and setting required
environment variables (`PATH`, `LD_LIBRARY_PATH`, `SDE_INSTALL`, etc.).

In order to run the K8S Infra Offload Solution, the host needs the following 
additional setup.
- Kernel 5.15: The host needs to have kernel 5.15 in order for the K8S solution
  to work. Install kernel 5.15 on host from the RPM file included in the official
  CI build.
- iproute2 package (min version 5.19): Intel IDPF driver supports creation of CDQ
  interfaces (dynamic ports) using the devlonk command which is part of the 
  iproute2 package. In order for dynamic port creation to work, minimum version
  of iproute2 needed is 5.19. iproute2 source tarball can be downloaded from 
  this link: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/. 
  Ensure the following dependencies are installed before building and installing
  iproute2 from source: libnl3, libmnl. These can be installed on Fedora with
  the following commands:
  ```bash
  dnf install libnl3-devel
  dnf install libmnl-devel
  ```
  iproute2 can then be installed by running `make` and `make install` in the 
  iproute2 source folder.
- IDPF driver: Due to the requirement of kernel upgrade to 5.15, the IDPF driver
  needs to be built from source. Before building the driver, install the kernel
  header files and kernel sources from RPMs included in the CI build files. Get
  the IDPF source also from included source RPM. Then run the following commands
  build and install the IDPF driver.
  ```bash
  cd <IDPF source base directory>
  make -j silicon
  make install
  ```

## Install IPDK SDE and IPDK Networking Recipe
IPDK infrap4d (P4 Control Plane) needs to be installed and run on the host
natively. To install infrap4d and P4-SDE (components as per IPDK 23.07 release)
individually, follow the instructions listed below. Note that, P4C is not
required as this software includes P4C generated artifacts.
 
### P4-SDE
  To install P4-SDE, follow its README instructions in the SDE package.
  Make sure to checkout the appropriate branch or SHA meant for IPDK 23.07
  release. The main steps can be summerized as:

  Clone SDE repository, create install directory, setup environment variable and
  then build
  ```bash
  git clone <SDE Git Repository Link>
  cd p4-es2k-target
  git checkout <Branch/SHA for IPDK 23.07>
  git submodule update --init --recursive --force
  mkdir install
  export SDE=$PWD
  cd ./tools/setup
  source p4sde_env_setup.sh $SDE
  cd $SDE
  ./build-p4sde.sh -s $SDE_INSTALL
  ```

### Infrap4d
  To install infrap4d, follow instructions at
  https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/es2k-guide.md
  Make sure to checkout the appropriate
  branch or SHA meant for IPDK 23.07 release. The main steps can be summerized as:
  ```bash
  git clone https://github.com/ipdk-io/networking-recipe.git ipdk.recipe
  cd ipdk.recipe
  git checkout <Branch/SHA for IPDK 23.07>
  git submodule update --init --recursive
  export IPDK_RECIPE=$PWD
  mkdir install
  export DEPEND_INSTALL=$PWD/install
  cd $IPDK_RECIPE/setup
  cmake -B build -DCMAKE_INSTALL_PREFIX=$DEPEND_INSTALL
  cmake --build build [-j<njobs>]

  cd $IPDK_RECIPE
  source ./scripts/es2k/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  ./make-all.sh --target=es2k
  ./scripts/es2k/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL
  ```
