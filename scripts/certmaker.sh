# Certificate trees generated:
#
# 4. Energy Sector Trust Framework Signing CA
#     5. Energy Sector Trust Framework Signing Issuer
#          6. Application One (roles: supply-voltage-reader, reporter)
#          7. Application Two (roles: consumption-reader, reporter)
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

# 4. Energy Sector Trust Framework Signing CA
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 4-signing-ca-key.pem
openssl req -new -x509 -key 4-signing-ca-key.pem -out 4-signing-ca-cert.pem -days 3560 \
    -subj "/C=GB/O=Energy Sector Trust Framework/CN=Energy Sector Trust Framework Signing CA"

# 5. Energy Sector Trust Framework Signing Issuer
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 5-signing-issuer-key.pem
openssl req -new -key 5-signing-issuer-key.pem -out 5-signing-issuer-csr.pem \
    -subj "/C=GB/ST=London/O=Energy Sector Trust Framework/CN=Energy Sector Trust Framework Signing Issuer"
openssl x509 -req -in 5-signing-issuer-csr.pem -out 5-signing-issuer-ca.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_ca -CA 4-signing-ca-cert.pem -CAkey 4-signing-ca-key.pem -days 365

# 6. Application One (roles: supply-voltage-reader, reporter)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 6-application-one-key.pem
openssl req -new -key 6-application-one-key.pem -out 6-application-one-csr.pem \
    -subj "/C=GB/ST=London/O=Application One/CN=https:\/\/directory.estf.ib1.org\/member\/2876152"
openssl x509 -req -in 6-application-one-csr.pem -out 6-application-one-cert.pem -extfile ../scripts/roles.cnf -extensions roles1 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365 -set_serial 123456
cat 6-application-one-cert.pem 5-signing-issuer-ca.pem > 123456-bundle.pem

# 7. Application Two (roles: consumption-reader, reporter)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 7-application-two-key.pem
openssl req -new -key 7-application-two-key.pem -out 7-application-two-csr.pem \
    -subj "/C=GB/ST=London/O=Application Two/CN=https:\/\/directory.estf.ib1.org\/member\/81524"
openssl x509 -req -in 7-application-two-csr.pem -out 7-application-two-cert.pem -extfile ../scripts/roles.cnf -extensions roles2 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365 -set_serial 98765
cat 7-application-two-cert.pem 5-signing-issuer-ca.pem > 98765-bundle.pem

openssl x509 -in 6-application-one-cert.pem -noout -text
openssl x509 -in 7-application-two-cert.pem -noout -text
