# Using TLS Certificates

This document provides information about generating and installing TLS
certificates for running k8s-infra-offload recipe.

## Generating certificates
The system relies on mTLS (mutual TLS) for authentication.

Ensure that the IP of the inframanager and infraagent are present
in the list in the config [openssl.cnf file](scripts/tls/openssl.cnf)
```bash
DNS.1 = *.intel.com
DNS.2 = k8s
DNS.3 = kubernetes.default
IP.1  = 127.0.0.1
IP.2  = 10.10.0.2 # Inframanager IP here for example
```

This config file is used to generate Certificate Signing Request (CSR)
files for each 
1. InfraAgentClient
2. InfraMgrServer
3. InfraMgrClient
4. Infrap4d

Run the below from base directory.
```bash
make gen-certs
```
The files will be generated under
```bash
$BASE_DIR/tls/certs/infraagent/client   #InfraAgentClient
$BASE_DIR/tls/certs/inframanager/server #InfraMgrServer
$BASE_DIR/tls/certs/inframanager/client #InfraMgrClient
$BASE_DIR/tls/certs/infrap4d #infrap4d
```

## Installing certificates

`infrap4d` will check for server certificates in the default location
`/usr/share/stratum/certs/`.

inframanager and infraagent will be expecting certificates in the
location `/etc/pki/inframanager/certs` and `/etc/pki/infraagent/certs`
respectively.


For more information regarding default and non-default path, refer to
[inframanager-config-file section](docs/setup.md#inframanager-config-file-update)
