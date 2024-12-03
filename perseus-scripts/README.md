# Perseus Pilot Provenance generation scripts

## Energy Data Provider

Populate the `perseus-scripts/in-edp` directory with:

* `signing-ca-root.pem` -- Root certificate of the Signing CA, provided by IB1
* `signer-cert-bundle.pem` -- Directory issued Signing certificate bundle
* `signer.key` -- Key associated with the Signing certificate

Then edit `perseus-scripts/in-edp/details.json` with the details for the Provenance record.

With the current directory at the root of the repository, run:

```
python3 perseus-scripts/generate-edp-record.py
```

`perseus-scripts/out` will now contain the signed and encoded record in `edp-record.json`, along with decoded and Graphviz representations.

