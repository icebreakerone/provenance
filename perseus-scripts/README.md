# Perseus Pilot Provenance generation scripts

## Energy Data Provider

Populate the `perseus-scripts/in-edp` directory with:

* `signing-ca-root.pem` -- Root certificate of the Signing CA, provided by IB1
* `signer-cert-bundle.pem` -- Directory issued Signing certificate bundle
* `signer.key` -- Key associated with the Signing certificate

Then edit `perseus-scripts/in-edp/details.json` with the details for the Provenance record.

With the current directory at the root of the repository, run:

```
mkdir -p perseus-scripts/out
python3 perseus-scripts/generate-edp-record.py
```

`perseus-scripts/out` will now contain the signed and encoded record in `edp-record.json`, along with decoded and Graphviz representations.

## Carbon Accounting Provider

Populate the `perseus-scripts/in-cap` directory with:

* `edp-record.json` -- Signed Provenance record as received from the EDP
* `signing-ca-root.pem` -- Root certificate of the Signing CA, provided by IB1
* `signer-cert-bundle.pem` -- Directory issued Signing certificate bundle
* `signer.key` -- Key associated with the Signing certificate

Then edit `perseus-scripts/in-cap/details.json` with the details for the Provenance record.

With the current directory at the root of the repository, run:

```
mkdir -p perseus-scripts/out
python3 perseus-scripts/generate-cap-record.py
```

`perseus-scripts/out` will now contain the signed and encoded record in `cap-record.json`, along with decoded and Graphviz representations.

The final record can also be decoded with:

```
python3 decode-self-contained-provenance.py perseus-scripts/in-cap/signing-ca-root.pem < perseus-scripts/out/cap-record.json
```
