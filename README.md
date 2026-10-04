# Filter
Web filtering for schools made easy

Canopy Filter works with a mix of domain and content filtering, it can be used without a device agent, just a proxy server, which means that deployment is super simple, enforce the proxy server, and trust the mitm cert.

## Trusting the MITM certificate on Linux

Inspected HTTPS traffic is re-signed by `certs/ca.crt`. The client browser must trust this certificate or it will report `tls: unknown certificate authority`.

Generate the CA if needed:

```bash
./utils/generatecerts.sh
```

On Windows, use the batch equivalent (requires OpenSSL on `PATH`, e.g. from Git for Windows):

```bat
utils\generatecerts.bat
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

## Running the tests

```bash
go test ./...
```

The Postgres tests in `pkg/filter` run the real rules query and `db/schema.sql`, and are skipped unless `TEST_DATABASE_URL` is set. Each test works in its own temporary schema, so any database you point it at is left untouched, but use a throwaway one:

```bash
docker run --rm -d --name canopy-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=canopy_test -p 54329:5432 postgres:17
TEST_DATABASE_URL='postgres://postgres:test@localhost:54329/canopy_test?sslmode=disable' go test ./...
docker stop canopy-test-pg
```
