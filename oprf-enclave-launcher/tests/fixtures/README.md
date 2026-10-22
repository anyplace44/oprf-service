# Fixtures for `src/recipient.rs`

## OpenSSL envelopes

`recipient-key.pk8` is a **test-only** RSA-2048 key generated for these fixtures. It protects
nothing; never use it outside tests.

Generated with OpenSSL 4.0.3 (29 Sep 2026), Homebrew `/opt/homebrew/opt/openssl@4/bin/openssl`
(LibreSSL's `/usr/bin/openssl` cannot produce OAEP-SHA256 CMS). OpenSSL is the independent
implementation the decryptor is checked against. `-stream` produces indefinite-length BER, which
is what KMS returns; without it the output is DER.

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k.pem
openssl pkcs8 -topk8 -nocrypt -in k.pem -outform DER -out recipient-key.pk8
openssl req -new -x509 -key k.pem -subj /CN=test -days 1 -out c.pem
printf '%s' '{"environment":{"A":"1"},"forwards":""}' > plaintext.json
openssl cms -encrypt -binary -aes256 -recip c.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 -in plaintext.json -outform DER -out envelope.der
openssl cms -encrypt -binary -stream -aes256 -recip c.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 -in plaintext.json -outform DER -out envelope-ber.der
openssl cms -encrypt -binary -aes128 -recip c.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 -in plaintext.json -outform DER -out envelope-aes128.der
```

`k.pem` and `c.pem` are not kept. `envelope-ber.der` carries its content in two OCTET STRING
segments, so it also covers segment concatenation. `envelope-aes128.der` exists to check that an
unsupported content cipher is rejected by name.

## AWS KMS responses

`aws_kms_response.rs` holds the two recorded KMS `CiphertextForRecipient` responses
(`input_ber`, `input_ber_w_ctx`) and their expected encrypted key, IV and ciphertext, copied byte
for byte from AWS's own Nitro Enclaves client:

- Repository: <https://github.com/aws/aws-nitro-enclaves-sdk-c>
- Commit: `cd61b6187c8b20867ba4368d1ae62c5790c0269a`
- File: `tests/kmstool-enclaves/cms_test.c` (parser: `source/cms.c`)
- Licence: Apache-2.0, Copyright 2020-2022 Amazon.com, Inc. or its affiliates.

No private key exists for them, so they test parsing only.
