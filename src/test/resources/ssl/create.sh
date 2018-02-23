#!/bin/bash -e

DAYS=${DAYS:=3650}
OPENSSL=$(which openssl)
KEYTOOL=$(which keytool)

# Create private key and self-signed certificate
$OPENSSL req -x509 -days "${DAYS}" -nodes -newkey rsa:2048 -config openssl-selfsigned.cnf -keyout pkcs5-plain.pem -out selfsigned.pem
# Convert PKCS#5 private key to PKCS#8 private key
$OPENSSL pkcs8 -in pkcs5-plain.pem -topk8 -nocrypt -out cert-key.pem

# Create CA key and certificate
$OPENSSL req -x509 -nodes -newkey rsa:2048 -extensions v3_ca -config openssl-ca.cnf -keyout ca-key.pem -out ca-root.pem

# Create server certificate and sign with CA
$OPENSSL req -new -config openssl-ca.cnf -extensions server_cert -key cert-key.pem -out server-cert.csr
$OPENSSL x509 -req -in server-cert.csr -CA ca-root.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days "${DAYS}" -sha512
cat ca-root.pem >> server-cert.pem

# Create client certificate and sign with CA
$OPENSSL req -new -config openssl-ca.cnf -extensions client_cert -key cert-key.pem -out client-cert.csr
$OPENSSL x509 -req -in client-cert.csr -CA ca-root.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days "${DAYS}" -sha512
cat ca-root.pem >> client-cert.pem

$KEYTOOL -importcert -keystore cacerts.jks -storepass changeit -alias ca-cert -file ca-root.pem -noprompt -trustcacerts
