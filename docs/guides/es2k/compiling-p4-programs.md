# Compiling P4 Programs for ES2K

## 1. Overview

This document explains how to install the Intel&reg; IPU E2100 P4 Compiler
(`p4c-pna-xxp`) and Configurable Pipeline Tool (`cpt`), and use
them to compile a P4 program

## 2. Installing the P4 Compiler and Tools

### 2.1 Install RPMs

Install the `cpt`, `p4c-pna-xxp`, and `p4-sde` packages on a Fedora 37 x86_64 server,
from RPMs in the release tarball.

  Extract RPMs from the tarball
  ```bash
  tar xvzf mev-hw-b0-<release>-fedora37.tgz
  cd host/packages/x86_64/
  ```

  Install RPMs on server
  ```bash
  rpm -i cpt-<version>-ci.ts.release.<xxxx>.ehb0.5.15.fc37.x86_64.rpm
  dnf localinstall p4c*.rpm --allowerasing
  dnf localinstall p4-sde*.rpm --allowerasing
  ```

The packages will be installed under `/usr` directory. Note that these
RPMs are not relocatable.

### 2.2 Confirm tool versions

After installing the RPMs, verify the version numbers of the executables:

Set environment variables
```bash
export LD_LIBRARY_PATH=/usr/lib:/usr/lib64:/usr/local/lib:/usr/local/lib64:$LD_LIBRARY_PATH
```
```bash
cpt --version
```
```text
Intel(R) Configurable Pipeline Tool Version 3.8.0.16
Copyright (C) 2022 Intel Corporation.  All rights reserved.
```

```bash
p4c-pna-xxp --version
```
```text
p4c-pna-xxp
Version 3.0.70.7
```

### 2.3 Address "no such file" error

If the `p4c-pna-xxp --version` command displays the following error message:

```text
error while loading shared libraries: libboost_iostreams.so.1.69.0:\
cannot open shared object file: No such file or directory
```

You will need to download and install the correct version of the Boost
libraries.

```bash
wget https://boostorg.jfrog.io/artifactory/main/release/1.69.0/source/boost_1_69_0.tar.gz
tar -xf boost_1_69_0.tar.gz
cd boost_1_69_0/
./bootstrap.sh
./b2
./b2 install
```

Verify the compiler version number:

```bash
p4c-pna-xxp --version
```
```text
p4c-pna-xxp
Version 3.0.70.7
```

The compiler should now be ready for use.


## 3. Compiling a P4 Program

The `k8s_dp/es2k` directory contains the reference P4 

Use `p4c-pna-xxp` to compile a P4 program.

```bash
# Set environment variables
export LD_LIBRARY_PATH=/usr/lib:/usr/lib64:/usr/local/lib:/usr/local/lib64:$LD_LIBRARY_PATH
export OUTPUT_DIR=k8s_dp/es2k/

# Compile p4 program
p4c-pna-xxp -I/usr/lib -I/usr/share/p4c/p4include -I/usr/share/p4c/idpf-lib \
            $OUTPUT_DIR/k8s_dp.p4 -o $OUTPUT_DIR/k8s_dp.pb.bin \
            --p4runtime-files $OUTPUT_DIR/k8s_dp.p4info.txt \
            --context $OUTPUT_DIR/k8s_dp.context.json \
            --bfrt $OUTPUT_DIR/k8s_dp.bf-rt.json
```

The compiler will generate the following files:

- k8s_dp.p4info.txt
- k8s_dp.bf-rt.json
- k8s_dp.context.json
- k8s_dp.pb.bin

These files are called _P4 artifacts_.

## 5. Generating a Pkg File

Use `cpt` to prepare the P4 artifacts for deployment:

```bash
cpt --npic --format csr --pbd  -o k8s_dp.pkg \
    cpt_ver.s k8s_dp.pb.bin
```

Please see [Deploy P4 Kubernetes](../../Setup.md#Deploy-P4-Kubernetes)
for details about deployment.
