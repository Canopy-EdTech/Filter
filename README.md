# Filter
Web filtering for schools made easy

Canopy Filter works with a mix of domain and content filtering, it can be used without a device agent, just a proxy server, which means that deployment is super simple, enforce the proxy server, and trust the mitm cert.

## Trusting the MITM certificate on Linux

Inspected HTTPS traffic is re-signed by `certs/ca.crt`. The client browser must trust this certificate or it will report `tls: unknown certificate authority`.

Generate the CA if needed:

```bash
./utils/generatecerts.sh
```

For Firefox, open **Settings > Privacy & Security > Certificates > View Certificates > Authorities**, import `certs/ca.crt`, and enable trust for websites.

For Chromium-based browsers using the system certificate store:

```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/canopy-filter-mitm.crt
sudo update-ca-certificates
```

Restart the browser after installing the certificate. Never install or share `certs/ca.key`; it is the private MITM key.

To test without changing the browser trust store, use `curl` with the CA explicitly:

```bash
curl -v --cacert certs/ca.crt --noproxy "" \
	-x http://127.0.0.1:8080 \
	https://example.org/
```
