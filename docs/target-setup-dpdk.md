# Target Setup for P4-DPDK

## Install IPDK SDE and IPDK Networking Recipe for host mode
IPDK infrap4d (P4 Control Plane) needs to be installed and run on the host
natively. To install infrap4d and P4-SDE
individually, follow the instructions listed below. Note that, P4C is not
required as this software includes P4C generated artifacts.
 
### P4-SDE
  To install P4-SDE, follow its README instructions at
  https://github.com/p4lang/p4-dpdk-target. Make sure to checkout the appropriate
  branch or SHA meant for the right release. The main steps can be summerized as:

  Clone SDE repository, create install directory, setup environment variable and
  then build
  ```bash
  git clone https://github.com/p4lang/p4-dpdk-target.git
  cd p4-dpdk-target
  git checkout <Branch/SHA for IPDK 24.01>
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
  https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/dpdk-guide.md.
  Make sure to checkout the appropriate
  branch or SHA meant for the right IPDK release. The main steps can be summerized as:
  ```bash
  git clone https://github.com/ipdk-io/networking-recipe.git ipdk.recipe
  cd ipdk.recipe
  git checkout <Branch/SHA for IPDK 24.01>
  git submodule update --init --recursive
  export IPDK_RECIPE=$PWD
  mkdir install
  export DEPEND_INSTALL=$PWD/install
  cd $IPDK_RECIPE/setup
  cmake -B build -DCMAKE_INSTALL_PREFIX=$DEPEND_INSTALL
  cmake --build build [-j<njobs>]

  cd $IPDK_RECIPE
  source ./scripts/dpdk/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  ./make-all.sh --target=dpdk
  ./scripts/dpdk/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL
  ```
