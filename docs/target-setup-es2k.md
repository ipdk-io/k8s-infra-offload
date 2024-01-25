# Target Setup for Intel IPU E2100

## Set Up Hardware Board

Hardware setup requires the Intel IPU device to be connected to a link partner
in a back-to-back manner. Refer to the setup topology in the
FXP_P4_SDE_User_Guide.md included in the documentation in official release
for details. This document also provides instructions on how to configure the
machine with required BIOS settings, required third-party software, boot
instructions, and system settings, as well as other information.

Follow the SDE User Guide with all the steps until ipumgmtd is started.

Perform following steps to setup k8s_dp custom package and node policy
config file prior to rebooting imc.

## Copy Custom Package and cp_init Config to IMC

K8s uses a custom p4 package for the datapath. The p4 artifacts for
this custom program are pre-generated in the package provided by Intel.
Please use these artifacts and put them under k8s_dp/es2k dir of k8s source.
If any modifications are made, use the following instructions on
compilation under [Compile K8s P4](#compile-k8s-p4)
section of this guide. The default cp_init.cfg file would need changes for subfunction support
on the host. An example file called `cp_init_use_case_cdq.cfg` has been provided.

Copy fxp-net_k8s-dp.pkg to IMC '/work/scripts' dir from the link partner machine.

  ```bash
  scp fxp-net_k8s-dp.pkg 100.0.0.100:/work/scripts/.
  ```

  On IMC:
  Modify load_custom_pkg.sh as below:

  ```bash
  cd /work/scripts
  cp /etc/dpcp/cp_init_use_case_cdq.cfg cp_init.cfg
  ```

  ```bash
  cat load_custom_pkg.sh
  ```
  Modify the script `load_custom_pkg.sh`
  so that it looks like the below

  ```bash
  #!/bin/sh
  CP_INIT_CFG=/etc/dpcp/cfg/cp_init.cfg
  echo "Checking for custom package..."
  if [ -e fxp-net_k8s-dp.pkg ]; then
      echo "Custom package p4_custom.pkg found. Overriding default package"
      cp  fxp-net_k8s-dp.pkg /etc/dpcp/package/
      cp  cp_init.cfg /etc/dpcp/cfg/
      rm -rf /etc/dpcp/package/default_pkg.pkg
      ln -s /etc/dpcp/package/fxp-net_k8s-dp.pkg /etc/dpcp/package/default_pkg.pkg
      sed -i 's/sem_num_pages = 1;/sem_num_pages = 25;/g' $CP_INIT_CFG
      sed -i 's/lem_num_pages = 1;/lem_num_pages = 25;/g' $CP_INIT_CFG
  else
      echo "No custom package found. Continuing with default package"
  fi
  ```

The work directory on IMC is persistent so any config and package files
copied here, will continue to exist over subsequent reboots.

## Set up Host

Follow the steps listed in the FXP P4 SDE User Guide document for host setup.
The steps include configuring Linux kernel boot parameters to
enable IOMMU, ATE, etc.; installing ATE kernel and other RPMs; installing
required third-party software; installing p4sde and p4-cp-nws.

## Install out-of-tree IDPF Driver

IDPF driver creates subfunction interfaces which are allocated to Pods.
Please refer to the IDPF documentation on how to install (or build if required for
the right version). Documentation under features/networking/IDPF_Readme.rst in the 
documentation tarball

## Install IPDK SDE and IPDK Networking Recipe

For K8s recipe on host, IPDK p4-cp-nws (p4-control) and p4-sde components need to be installed
and run on the host natively.
To install p4sde, follow the instructions in FXP P4SDE User Guide.

To install infrap4d which is the networking recipe, follow instructions at
https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/setup/es2k-setup-guide.md
Make sure to checkout the appropriate

## Install P4C

P4 PNA compiler is used to build P4 compiled artifacts. The source distribution
for CPT and P4C is under in the p4-programs release tarball hw-p4-programs.xxxx.tgz.

## Compile K8s P4

The P4 Programs User Guide describes how to build packages and
artifacts for a sample P4 program. See the Build Custom Package
section in the Intel P4 Programs Readme for detailed instructions.
To build the k8s datapath p4 artifacts, follow the instructions below once compiler
is installed and all the env variables required by the makefile are set.

```bash
make fxp-net_k8s-dp
```

### Building p4runtime pipeline builder file
This command is required to be run on all the artifacts. The pipeline builder serializes the artifacts to be sent over
the p4runtime SetForwardingPipelineConfigRequest. This needs to be run on the ACC for split mode.

```bash
touch <file_path>/tofino.bin
/opt/p4/p4-cp-nws/bin/tdi_pipeline_builder  -p4c_conf_file=/usr/share/stratum/es2k/es2k_skip_p4.conf  -bf_pipeline_config_binary_file=<file_path>/k8s_dp.pb.bin
```

## Generating certificates

Refer to the file [security-guide.md](security/security-guide.md) for more details on generating and installing certificates
