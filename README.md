# Provenance

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

pipx install poetry
poetry install

mkdir certs
cd certs
sh ../scripts/certmaker.sh

python3 main.py
```

## Provenance record decoder

```
python3 decode-self-contained-provenance.py path/to/signing-CA-root.pem < record.json
```
