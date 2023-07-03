# Install IPDK Networking Recipe
IPDK infrap4d needs to be installed and run on the host natively. To install
infrap4d and P4-SDE (components as per IPDK 23.07 release) individually, follow
the instructions listed below. Note that, P4C is not required as this software
includes P4C generated artifacts.
 
## P4-SDE
  To install P4-SDE, follow its README instructions at <TBD>
  Make sure to checkout the appropriate branch or SHA meant for IPDK 23.07
  release. The main steps can be summerized as:

  Clone SDE repository, create install directory, setup environment variable and
  then build
  ```bash
  # git clone <TBD>
  # cd p4-es2k-target
  # git checkout <Branch/SHA for IPDK 23.07>
  # git submodule update --init --recursive --force
  # mkdir install
  # export SDE=$PWD
  # cd ./tools/setup
  # source p4sde_env_setup.sh $SDE
  # cd $SDE
  # ./build-p4sde.sh -s $SDE_INSTALL
  ```

## Infrap4d
  To install infrap4d, follow instructions at
  https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/es2k-guide.md
  Make sure to checkout the appropriate
  branch or SHA meant for IPDK 23.07 release. The main steps can be summerized as:
  ```bash
  # git clone https://github.com/ipdk-io/networking-recipe.git ipdk.recipe
  # cd ipdk.recipe
  # git checkout <Branch/SHA for IPDK 23.07>
  # git submodule update --init --recursive
  # export IPDK_RECIPE=$PWD
  # mkdir install
  # export DEPEND_INSTALL=$PWD/install
  # cd $IPDK_RECIPE/setup
  # cmake -B build -DCMAKE_INSTALL_PREFIX=$DEPEND_INSTALL
  # cmake --build build [-j<njobs>]

  # cd $IPDK_RECIPE
  # source ./scripts/es2k/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  # ./make-all.sh --target=es2k
  # ./scripts/es2k/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL
  ```

## Set Up Hardware Board

Hardware setup requires the Intel IPU device to be connected to a link partner
in a back-to-back manner. Refer to the setup topology in the
[P4 SDE User Guide](../../tools/p4_UserGuide/FXP_P4_SDE_User_Guide.md)
for details. This document also provides instructions on how to configure the
machine with required BIOS settings, required third-party software, boot
instructions, and system settings, as well as other information.

Follow the SDE User Guide with all the steps until ipumgmtd is started.

When configuring the `/etc/dpcp/cp_init.cfg` file as per the above steps,
change `package_file_suffix` to `k8s_dp-0.9.pkg`.

In addition, the Kubernetes Infrastructure Offload software requires the host 
to have Linux kernel 5.15 with IDPF driver built against it. Refer to the 
[IDPF readme](../host/IDPF_Readme.rst) for installation instructions.

Follow the steps listed in the SDE User Guide in the "Running from HOST" section.
The steps include configuring Linux kernel boot parameters to enable IOMMU, ATE,
etc.; installing ATE kernel and other RPMs; installing required third-party
software; installing p4sde and p4-cp-nws; loading drivers and binding them to
the device; configuring HugePages; and setting required environment variables
(`PATH`, `LD_LIBRARY_PATH`, `SDE_INSTALL`, etc.).
