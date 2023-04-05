#!/bin/bash
set -e

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"
CERTS=certs
OPENSSL_CNF=openssl.cnf
AGENT_CLIENT=$CERTS/infraagent/client
MGR_CLIENT=$CERTS/inframanager/client
MGR_SERVER=$CERTS/inframanager/server
INFRAP4D=$CERTS/infrap4d/certs

[ -d $CERTS ] && rm -rf $CERTS
mkdir -p $CERTS
mkdir -p $AGENT_CLIENT
mkdir -p $MGR_CLIENT
mkdir -p $MGR_SERVER
mkdir -p $INFRAP4D

# Create common self-signed CA cert 
openssl req -x509                                          \
  -newkey rsa:4096                                         \
  -nodes                                                   \
  -days 365                                                \
  -keyout $CERTS/ca.key                                    \
  -out $CERTS/ca.crt                                       \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infra-server_ca/        \
  -config $OPENSSL_CNF                                     \
  -extensions v3_ca                                        \
  -sha384


# Copy CA cert to Agent and Manager specific dirs
cp $CERTS/ca.crt $AGENT_CLIENT
cp $CERTS/ca.crt $MGR_CLIENT
cp $CERTS/ca.crt $MGR_SERVER
cp $CERTS/ca.crt $INFRAP4D

# Generate inframanager server csr and sign it
# with CA.
openssl genrsa -out $MGR_SERVER/tls.key 4096
openssl req -new                                        \
  -key $MGR_SERVER/tls.key                              \
  -out $MGR_SERVER/server.csr                           \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=inframanager-server/ \
  -config $OPENSSL_CNF                                  \
  -reqexts v3_server
openssl x509 -req                                       \
  -in $MGR_SERVER/server.csr                            \
  -CAkey $CERTS/ca.key                                  \
  -CA $CERTS/ca.crt                                     \
  -days 365                                             \
  -set_serial 1000                                      \
  -out $MGR_SERVER/tls.crt                              \
  -extfile $OPENSSL_CNF                                 \
  -extensions v3_server                                 \
  -sha384
openssl verify -verbose -CAfile $CERTS/ca.crt $MGR_SERVER/tls.crt
rm $MGR_SERVER/server.csr

# Generate inframanager client csr and sign it
# with CA.
openssl genrsa -out $MGR_CLIENT/tls.key 4096
openssl req -new                                        \
  -key $MGR_CLIENT/tls.key                              \
  -out $MGR_CLIENT/client.csr                           \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=inframanager-server/ \
  -config $OPENSSL_CNF                                  \
  -reqexts v3_server
openssl x509 -req                                       \
  -in $MGR_CLIENT/client.csr                            \
  -CAkey $CERTS/ca.key                                  \
  -CA $CERTS/ca.crt                                     \
  -days 365                                             \
  -set_serial 1001                                      \
  -out $MGR_CLIENT/tls.crt                              \
  -extfile $OPENSSL_CNF                                 \
  -extensions v3_server                                 \
  -sha384
openssl verify -verbose -CAfile $CERTS/ca.crt $MGR_CLIENT/tls.crt
rm $MGR_CLIENT/client.csr


# Generate infraagent client csr and sign it
# with CA.
openssl genrsa -out $AGENT_CLIENT/tls.key 4096
openssl req -new                                        \
  -key $AGENT_CLIENT/tls.key                            \
  -out $AGENT_CLIENT/client.csr                         \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=infraagent-client/   \
  -config $OPENSSL_CNF                                  \
  -reqexts v3_server
openssl x509 -req                                       \
  -in $AGENT_CLIENT/client.csr                          \
  -CAkey $CERTS/ca.key                                  \
  -CA $CERTS/ca.crt                                     \
  -days 365                                             \
  -set_serial 1002                                      \
  -out $AGENT_CLIENT/tls.crt                            \
  -extfile $OPENSSL_CNF                                 \
  -extensions v3_server                                 \
  -sha384
openssl verify -verbose -CAfile $CERTS/ca.crt $AGENT_CLIENT/tls.crt
rm $AGENT_CLIENT/client.csr

# Generate infrap4d server csr and sign it
# with CA.
openssl genrsa -out $INFRAP4D/stratum.key 4096
openssl req -new                                        \
  -key $INFRAP4D/stratum.key                            \
  -out $INFRAP4D/stratum.csr                            \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN=localhost/           \
  -config $OPENSSL_CNF                                  \
  -reqexts v3_stratum_server
openssl x509 -req                                       \
  -in $INFRAP4D/stratum.csr                             \
  -CAkey $CERTS/ca.key                                  \
  -CA $CERTS/ca.crt                                     \
  -days 365                                             \
  -set_serial 1003                                      \
  -out $INFRAP4D/stratum.crt                            \
  -extfile $OPENSSL_CNF                                 \
  -extensions v3_stratum_server                         \
  -sha512
openssl verify -verbose -CAfile $CERTS/ca.crt $INFRAP4D/stratum.crt
rm $INFRAP4D/stratum.csr

# Generate infrap4d client csr and sign it
# with CA.
openssl genrsa -out $INFRAP4D/client.key 4096
openssl req -new                                                  \
  -key $INFRAP4D/client.key                                       \
  -out $INFRAP4D/client.csr                                       \
  -subj /C=US/ST=CA/L=SJ/O=IPDK/CN="Stratum client certificate"/  \
  -config $OPENSSL_CNF                                            \
  -reqexts v3_stratum_server
openssl x509 -req                                                 \
  -in $INFRAP4D/client.csr                                        \
  -CAkey $CERTS/ca.key                                            \
  -CA $CERTS/ca.crt                                               \
  -days 365                                                       \
  -set_serial 1004                                                \
  -out $INFRAP4D/client.crt                                       \
  -extfile $OPENSSL_CNF                                 \
  -extensions v3_stratum_server                         \
  -sha512
openssl verify -verbose -CAfile $CERTS/ca.crt $INFRAP4D/client.crt
rm $INFRAP4D/client.csr


