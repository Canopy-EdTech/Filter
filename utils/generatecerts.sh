#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(dirname -- "$script_dir")"
default_output_dir="$project_root/certs"

read -r -p "Certificate output directory [$default_output_dir]: " output_dir
output_dir="${output_dir:-$default_output_dir}"

read -r -p "Certificate common name [Canopy Filter MITM CA]: " common_name
common_name="${common_name:-Canopy Filter MITM CA}"

read -r -p "Organization [Canopy EdTech]: " organization
organization="${organization:-Canopy EdTech}"

read -r -p "Country code [US]: " country
country="${country:-US}"

read -r -p "Validity in days [3650]: " validity_days
validity_days="${validity_days:-3650}"

read -r -p "RSA key size [4096]: " key_size
key_size="${key_size:-4096}"

if [[ ! "$validity_days" =~ ^[1-9][0-9]*$ ]]; then
	echo "Validity must be a positive whole number." >&2
	exit 1
fi

if [[ ! "$key_size" =~ ^(2048|3072|4096|8192)$ ]]; then
	echo "Key size must be one of 2048, 3072, 4096, or 8192." >&2
	exit 1
fi

if [[ ! "$country" =~ ^[A-Za-z]{2}$ ]]; then
	echo "Country must be a two-letter code." >&2
	exit 1
fi

ca_key="$output_dir/ca.key"
ca_cert="$output_dir/ca.crt"

if [[ -e "$ca_key" || -e "$ca_cert" ]]; then
	read -r -p "Existing CA files found. Overwrite them? [y/N]: " overwrite
	if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
		echo "Aborted. Existing certificate files were not changed."
		exit 1
	fi
fi

mkdir -p "$output_dir"
umask 077

openssl genrsa -out "$ca_key" "$key_size"
openssl req -x509 -new -sha256 \
	-key "$ca_key" \
	-out "$ca_cert" \
	-days "$validity_days" \
	-subj "/C=${country^^}/O=$organization/CN=$common_name" \
	-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

chmod 600 "$ca_key"
chmod 644 "$ca_cert"

echo
echo "MITM CA generated:"
echo "  Certificate: $ca_cert"
echo "  Private key: $ca_key"
echo "Install the certificate on client devices, and keep the private key secret."
