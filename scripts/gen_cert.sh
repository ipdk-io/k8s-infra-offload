#!/bin/bash
set -ex

CERTS=./certs
OPENSSL_CNF=./scripts/openssl.cnf

[ -d $CERTS ] && rm -rf $CERTS
mkdir -p $CERTS

#Mutual TLS
# Create the CA certs for client and server.

# Create the server CA. 
openssl req -x509                                          \
  -newkey rsa:4096                                         \
  -nodes                                                   \
  -days 365                                                \
  -keyout $CERTS/infra-server-ca.key                       \
  -out $CERTS/infra-server-ca.crt                          \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infra-server_ca/        \
  -config $OPENSSL_CNF                                     \
  -extensions v3_ca                                        \
  -sha256

# Create the client CA. 
openssl req -x509                                          \
  -newkey rsa:4096                                         \
  -nodes                                                   \
  -days 365                                                \
  -keyout $CERTS/infra-client-ca.key                       \
  -out $CERTS/infra-client-ca.crt                          \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infra-client_ca/        \
  -config $OPENSSL_CNF                                     \
  -extensions v3_ca                                        \
  -sha256

# Generate inframanager server csr and sign it
# with server CA.
openssl genrsa -out $CERTS/inframgr-server.key 4096
openssl req -new                                        \
  -key $CERTS/inframgr-server.key                       \
  -out $CERTS/inframgr-server.csr                              \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=inframanager-server/ \
  -config $OPENSSL_CNF                                 \
  -reqexts v3_server
openssl x509 -req            \
  -in $CERTS/inframgr-server.csr    \
  -CAkey $CERTS/infra-server-ca.key \
  -CA $CERTS/infra-server-ca.crt    \
  -days 365                  \
  -set_serial 1000           \
  -out $CERTS/inframgr-server.crt   \
  -extfile $OPENSSL_CNF     \
  -extensions v3_server      \
  -sha256
openssl verify -verbose -CAfile $CERTS/infra-server-ca.crt $CERTS/inframgr-server.crt

# Generate inframanager client csr and sign it
# with client CA.
openssl genrsa -out $CERTS/inframgr-client.key 4096
openssl req -new                                        \
  -key $CERTS/inframgr-client.key                              \
  -out $CERTS/inframgr-client.csr                              \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=inframanager-client/ \
  -config $OPENSSL_CNF                                 \
  -reqexts v3_server
openssl x509 -req             \
  -in $CERTS/inframgr-client.csr     \
  -CAkey $CERTS/infra-client-ca.key  \
  -CA $CERTS/infra-client-ca.crt     \
  -days 365                   \
  -set_serial 1000            \
  -out $CERTS/inframgr-client.crt    \
  -extfile $OPENSSL_CNF      \
  -extensions v3_server       \
  -sha256
openssl verify -verbose -CAfile $CERTS/infra-client-ca.crt $CERTS/inframgr-client.crt

# Generate infraagent server csr and sign it
# with server CA.
openssl genrsa -out $CERTS/infraagent-server.key 4096
openssl req -new                                        \
  -key $CERTS/infraagent-server.key                            \
  -out $CERTS/infraagent-server.csr                            \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infraagent-server/   \
  -config $OPENSSL_CNF                                 \
  -reqexts v3_server
openssl x509 -req            \
  -in $CERTS/infraagent-server.csr  \
  -CAkey $CERTS/infra-server-ca.key \
  -CA $CERTS/infra-server-ca.crt    \
  -days 365                  \
  -set_serial 1000           \
  -out $CERTS/infraagent-server.crt \
  -extfile $OPENSSL_CNF     \
  -extensions v3_server      \
  -sha256
openssl verify -verbose -CAfile $CERTS/infra-server-ca.crt $CERTS/infraagent-server.crt

# Generate infraagent client csr and sign it
# with client CA.
openssl genrsa -out $CERTS/infraagent-client.key 4096
openssl req -new                                        \
  -key $CERTS/infraagent-client.key                            \
  -out $CERTS/infraagent-client.csr                            \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infraagent-client/   \
  -config $OPENSSL_CNF                                \
  -reqexts v3_server
openssl x509 -req             \
  -in $CERTS/infraagent-client.csr   \
  -CAkey $CERTS/infra-client-ca.key  \
  -CA $CERTS/infra-client-ca.crt     \
  -days 365                   \
  -set_serial 1000            \
  -out $CERTS/infraagent-client.crt  \
  -extfile $OPENSSL_CNF      \
  -extensions v3_server       \
  -sha256
openssl verify -verbose -CAfile $CERTS/infra-client-ca.crt $CERTS/infraagent-client.crt

rm $CERTS/*.csr
