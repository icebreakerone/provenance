# Certificate trees generated:
#
# 4. Core Trust Framework Signing CA
#     5. Core Trust Framework Signing Issuer
#          6. Honest Dave's Accurate Meter Reading Co (roles: energy-data-provider)
#          7. Emission Calculations 4 U (roles: carbon-accounting-platform)
#          8. Green Bank of London (roles: finance-provider, auditor)
#
# Use serial numbers which are easy to spot in output, and make bundles based on serial numbers.
#
# Use EC keys, with the P-256 curve used in JWS.

set -e

if ! which openssl
then
    echo "openssl must be in your PATH" >&2
    exit 1
fi

# 4. Core Trust Framework Signing CA
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 4-signing-ca-key.pem
openssl req -new -key 4-signing-ca-key.pem -out 4-signing-ca-csr.pem \
    -subj "/C=GB/O=Core Trust Framework/CN=Core Trust Framework Signing CA"
openssl x509 -req -in 4-signing-ca-csr.pem -out 4-signing-ca-cert.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_ca -key 4-signing-ca-key.pem -days 3650

# 5. Core Trust Framework Signing Issuer
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 5-signing-issuer-key.pem
openssl req -new -key 5-signing-issuer-key.pem -out 5-signing-issuer-csr.pem \
    -subj "/C=GB/ST=London/O=Core Trust Framework/CN=Core Trust Framework Signing Issuer"
openssl x509 -req -in 5-signing-issuer-csr.pem -out 5-signing-issuer-ca.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_intermediate_ca -CA 4-signing-ca-cert.pem -CAkey 4-signing-ca-key.pem -days 365

# 6. Honest Dave's Accurate Meter Reading Co (roles: energy-data-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 6-honest-daves-accurate-meter-readings-key.pem
openssl req -new -key 6-honest-daves-accurate-meter-readings-key.pem -out 6-honest-daves-accurate-meter-readings-csr.pem \
    -subj "/C=GB/ST=London/O=Honest Dave's Accurate Meter Reading Co/CN=https:\/\/directory.core.trust.ib1.org\/member\/2876152"
openssl x509 -req -in 6-honest-daves-accurate-meter-readings-csr.pem -out 6-honest-daves-accurate-meter-readings-cert.pem -extfile ../scripts/roles.cnf -extensions roles1 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365 -set_serial 123456
cat 6-honest-daves-accurate-meter-readings-cert.pem 5-signing-issuer-ca.pem > 123456-bundle.pem

# 7. Emission Calculations 4 U (roles: carbon-accounting-platform)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 7-emission-calculations-4-u-key.pem
openssl req -new -key 7-emission-calculations-4-u-key.pem -out 7-emission-calculations-4-u-csr.pem \
    -subj "/C=GB/ST=London/O=Emission Calculations 4 U/CN=https:\/\/directory.core.trust.ib1.org\/member\/81524"
openssl x509 -req -in 7-emission-calculations-4-u-csr.pem -out 7-emission-calculations-4-u-cert.pem -extfile ../scripts/roles.cnf -extensions roles2 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365 -set_serial 98765
cat 7-emission-calculations-4-u-cert.pem 5-signing-issuer-ca.pem > 98765-bundle.pem

# 9. Green Bank of London (roles: finance-provider, auditor)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 8-green-bank-of-london-key.pem
openssl req -new -key 8-green-bank-of-london-key.pem -out 8-green-bank-of-london-csr.pem \
    -subj "/C=GB/ST=London/O=Green Bank of London/CN=https:\/\/directory.core.trust.ib1.org\/member\/71212388"
openssl x509 -req -in 8-green-bank-of-london-csr.pem -out 8-green-bank-of-london-cert.pem -extfile ../scripts/roles.cnf -extensions roles3 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365 -set_serial 88889999
cat 8-green-bank-of-london-cert.pem 5-signing-issuer-ca.pem > 88889999-bundle.pem

# openssl x509 -in 4-signing-ca-cert.pem -noout -text
# openssl x509 -in 5-signing-issuer-ca.pem -noout -text
# openssl x509 -in 6-honest-daves-accurate-meter-readings-cert.pem -noout -text
# openssl x509 -in 7-emission-calculations-4-u-cert.pem -noout -text
# openssl x509 -in 8-green-bank-of-london-cert.pem -noout -text
