# Using TLS Certificates

This document provides information about generating and installing TLS
certificates for running k8s-infra-offload recipe.

## Generating certificates
The system relies on mTLS (mutual TLS) for authentication.

IPs of the servers using TLS, should be here. If in host mode,
localhost is used so `127.0.0.1` works. But if in split mode,
ensure that the IP is present here.
in the list in the config `scripts/tls/openssl.cnf`
```bash
DNS.1 = *.intel.com
DNS.2 = k8s
DNS.3 = kubernetes.default
IP.1  = 127.0.0.1
IP.2  = 10.10.0.2 # Inframanager server IP here for example
```

This config file is used to generate Certificate Signing Request (CSR)
files for each 
1. Infraagent(client)
2. Inframanager(server)
3. Inframanager(client)
4. Infrap4d

Run the below from base directory.
```bash
make gen-certs
```
The files will be generated under
```bash
$BASE_DIR/tls/certs/infraagent/client   #Infraagent(client)
$BASE_DIR/tls/certs/inframanager/server #Inframanager(server)
$BASE_DIR/tls/certs/inframanager/client #Inframanager(client)
$BASE_DIR/tls/certs/infrap4d #infrap4d
```

## Installing certificates

`infrap4d` will check for server certificates in the default location
`/usr/share/stratum/certs/`.

inframanager and infraagent will be expecting certificates in the
location `/etc/pki/inframanager/certs` and `/etc/pki/infraagent/certs`
respectively.


For more information regarding default and non-default path, refer to
[inframanager-config-file section](../setup.md#inframanager-config-file-update)
