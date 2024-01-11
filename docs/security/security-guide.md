# Security Guide

This document provides information about secure and insecure
modes for K8s-infra-offload recipe and certificate management.

## TLS Certificates

The gRPC ports are secured using TLS certificates. 
There are 2 gRPC interfaces in the recipe.
1. infraagent(client) <-> inframanager(server)
2. inframanager(client) <-> infrap4d  (p4runtime)

A script and reference
configuration files are available to assist in generating certificates and
keys using OpenSSL for both the gRPC connections. You may use other
tools if you wish.

The [reference files](https://github.com/ipdk-io/k8s-infra-offload/tree/main/scripts/tls)
use a simple PKI where a self-signed key and certificate.
The root level Certificate Authority (CA) is used to generate server-side
key and cert files, and client-side key and cert files. This results in a
1-depth level certificate chain, which will suffice for validation and
confirmation but may not provide sufficient security for production systems.
It is highly recommended to use well-known CAs, and generate certificates at
multiple depth levels in order to conform to higher security standards.

See [Using TLS Certificates](using-tls-certificates.md)
for step by step guide to generate and install TLS certificates

