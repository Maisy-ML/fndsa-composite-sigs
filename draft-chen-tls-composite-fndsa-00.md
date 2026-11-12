---

stand_alone: true
ipr: trust200902
cat: info
submissiontype: IETF
area: Security
wg: TLS

docname: draft-chen-tls-composite-fndsa-00

title: Use of Composite FN-DSA Signatures in TLS 1.3
abbrev: TLS Composite FN-DSA
lang: en
kw:
  - Internet-Draft
  - Post-Quantum
  - TLS 1.3
  - Composite Signature
  - FN-DSA

author:
- name: Meiling Chen
  org: China Mobile
  city: BeiJing
  country: China
  email: chenmeiling@chinamobile.com
- name: Xueyan Song
  org: ZTE Corp.
  email: song.xueyan2@zte.com.cn

normative:
  RFC2119:
  RFC8174:
  RFC8446:
  I-D.chen-lamps-fndsa-composite-sigs:
    title: Composite FN-DSA for use in X.509 Public Key Infrastructure
    author:
      - name: M. Chen
    date: 2026-05-08
  TLSIANA:
    title: IANA Registry Updates for TLS and DTLS
    author:
      - name: J. A. Salowey
      - name: S. Turner
    date: 2025-07-21
    seriesinfo:
        Internet-Draft: draft-ietf-tls-rfc8447bis-15

informative:
  RFC5246:
  RFC9794:
  FIPS206:
    target: https://www.nist.gov/news-
              events/news/2024/08/nist-releases-first-3-finalized-post-
              quantum-encryption-standards
    title: FIPS 206, Fast-Fourier-Transform-based Digital Signature Algorithm
    author:
      - org: National Institute of Standards and Technology (NIST)
  I-D.sheffer-tls-pqc-continuity:
    title: PQC Continuity - Downgrade Protection for TLS Servers Migrating to PQC
    author:
      - name: Y. Sheffer
      - name: T. Reddy.K
    date: 2025-10-18
    seriesinfo:
      Internet-Draft: draft-sheffer-tls-pqc-continuity-00

--- abstract

Compositing the post-quantum FN-DSA signature with traditional signature algorithms provides protection against potential breaks in either component. This document specifies how such a composite signature can be used for authentication in TLS 1.3. This gives TLS deployments a hybrid authentication option during the transition to post-quantum cryptography.

--- middle

# Introduction

The advent of quantum computing poses a significant threat to current cryptographic systems. During the transition to post-quantum cryptography (PQC), cautious implementers may opt to combine post-quantunm and traditional cryptographic algorithms with the goal of preserving the intended security property as long as at least one component remains secure. Such mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids [RFC9794].

Composite FN-DSA combines the post-quantum signature algorithm FN-DSA [FIPS206] with a traditional signature algorithm in a single signature scheme. The composite signature construction is specified in [I-D.chen-lamps-fndsa-composite-sigs]. This document specifies how TLS 1.3 endpoints advertise support for Composite FN-DSA through the signature_algorithms and signature_algorithms_cert extensions and use it for authentication.

A key design goal of this specification is to ensure **consistency across the emerging post-quantum ecosystem**. To that end, the selection of algorithm pairings in this document is intentionally aligned with the choices made for ML-DSA in `draft-ietf-lamps-pq-composite-sigs`. This creates two clear security tiers, allowing organizations to treat FN-DSA and ML-DSA composites at the same security level as interchangeable from a policy perspective.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

"Composite FN-DSA" refers to a composite FN-DSA signature scheme as defined in [I-D.chen-lamps-fndsa-composite-sigs]. For brevity, this document uses `fndsa512` and `fndsa1024` in `SignatureScheme` names to refer to the `Falcon-padded-512` and `Falcon-padded-1024` variants, respectively.

# Composite FN-DSA Signature Schemes

As defined in [RFC8446], the `SignatureScheme` namespace is used for the negotiation of signature schemes. This document adds new `SignatureScheme` values for composite FN-DSA, organized into two tiers that mirror the ML-DSA composite strategy.

~~~~
enum {
    /* Tier 1 Composites (FN-DSA-512 based, mimicking ML-DSA-44) */
    fndsa512_rsa2048_pss_sha256(TBD1),
    fndsa512_rsa2048_pkcs15_sha256(TBD2),
    fndsa512_ecdsa_p256_sha256(TBD3),
    fndsa512_ed25519_sha256(TBD4),

    /* Tier 2 Composites (FN-DSA-1024 based, mimicking ML-DSA-87) */
    fndsa1024_rsa3072_pss_sha512(TBD5),
    fndsa1024_rsa3072_pkcs15_sha512(TBD6),
    fndsa1024_ecdsa_p384_sha512(TBD7),
    fndsa1024_ecdsa_p521_sha512(TBD8),
    fndsa1024_ecdsa_brainpoolP384r1_sha512(TBD9),
    fndsa1024_ed448_sha512(TBD10),

} SignatureScheme;
~~~~

Composite FN-DSA is treated as an opaque signature algorithm, similar to the "PureEdDSA" algorithms in TLS 1.3 (Section 4.2.3 of [RFC8446]). Any hash functions used are internal to the composite algorithm itself, as specified in [I-D.chen-lamps-fndsa-composite-sigs].

When a composite FN-DSA signature scheme is used in TLS, the signing and verification operations MUST be performed on the input data as constructed by TLS (Section 4.4.3 of [RFC8446]). This input is then passed to the composite signature primitive, which applies its own internal domain separation.

When a composite FN-DSA `SignatureScheme` is negotiated, the end-entity certificate presented in the TLS handshake MUST contain a public key compatible with that `SignatureScheme`.

The Composite FN-DSA signature generation and verification operations specified in Sections 4.3 and 4.4 of [I-D.chen-lamps-fndsa-composite-sigs] both take a context string parameter, `ctx`. In both operations, `ctx` precedes the pre-hash output in the message representative, providing domain separation by binding the signature to the application context. TLS 1.3 provides protocol-level domain separation through the role-specific context string included in the `CertificateVerify` signature input (e.g., "TLS 1.3, server CertificateVerify"), as specified in Section 4.4.3 of [RFC8446]. When generating or verifying a TLS 1.3 `CertificateVerify` signature with Composite FN-DSA, `ctx` MUST be the empty octet string.

The schemes defined in this document MUST NOT be used in TLS 1.2 [RFC5246].


# Signature Algorithm Restrictions

TLS 1.3 [RFC8446] does not support RSASSA-PKCS1-v1_5 for `CertificateVerify` signature. Accordingly, the `fndsa512_rsa2048_pkcs15_sha256` and `fndsa1024_rsa3072_pkcs15_sha512` defined in this document MUST NOT be used with the `signature_algorithms` extension or in `CertificateVerify` messages, but can only be used with the `signature_algorithms_cert` extention.

Endpoints MAY advertise these two values in the `signature_algorithms` extension.


# Selection Criteria for Composite Signature Algorithms

The composite signatures specified in this document are a curated set of cryptographic pairs, directly adopted from [I-D.chen-lamps-fndsa-composite-sigs]. The selection process was guided by a single, overriding principle:

- **Strictly Mirroring ML-DSA Composite Strategy:** The pairings for `fndsa512` are identical to those for `ML-DSA-44`, and the pairings for `fndsa1024` are identical to those for `ML-DSA-87`, as defined in `draft-ietf-lamps-pq-composite-sigs`.

This prescriptive approach ensures a consistent, two-tiered security model across the PQC signature landscape, simplifying policy development and promoting interoperability.

## Mapping TLS SignatureSchemes to Composite FN-DSA

The following table provides a mapping between the TLS `SignatureScheme` identifiers and the corresponding composite algorithm identifiers from [I-D.chen-lamps-fndsa-composite-sigs].

| TLS SignatureScheme                     | Composite FN-DSA OID Name                  |
| --------------------------------------- | ------------------------------------------ |
| `fndsa512_rsa2048_pss_sha256`             | `id-fnpadded512-rsa2048-pss-sha256`          |
| `fndsa512_rsa2048_pkcs15_sha256`          | `id-fnpadded512-rsa2048-pkcs15-sha256`       |
| `fndsa512_ecdsa_p256_sha256`              | `id-fnpadded512-ecdsa-p256-sha256`           |
| `fndsa512_ed25519_sha256`                 | `id-fnpadded512-ed25519-sha512`              |
| `fndsa1024_rsa3072_pss_sha512`            | `id-fnpadded1024-rsa3072-pss-sha512`         |
| `fndsa1024_rsa3072_pkcs15_sha512`         | `id-fnpadded1024-rsa3072-pkcs15-sha512`      |
| `fndsa1024_ecdsa_p384_sha512`             | `id-fnpadded1024-ecdsa-p384-sha512`          |
| `fndsa1024_ecdsa_p521_sha512`             | `id-fnpadded1024-ecdsa-p521-sha512`          |
| `fndsa1024_ecdsa_brainpoolP384r1_sha512`   | `id-fnpadded1024-ecdsa-brainpoolP384r1-sha512`|
| `fndsa1024_ed448_sha512`                  | `id-fnpadded1024-ed448-sha512`               |
{: #tbl-mapping title="Mapping TLS SignatureSchemes to Composite FN-DSA Identifiers"}

# Security Considerations {#Security}

The security considerations discussed in [I-D.chen-lamps-fndsa-composite-sigs] apply. The primary goal is to provide hybrid security, where the composite signature remains secure as long as at least one component algorithm remains secure.

Composite signature schemes do not in general preserve strong unforgeability (SUF-CMA) once the traditional component is broken. This does not impact TLS, which relies on existential unforgeability (EUF-CMA).

TLS clients that support both post-quantum and traditional-only signature algorithms are vulnerable to downgrade attacks. The continuity mechanism defined in [I-D.sheffer-tls-pqc-continuity] can be used to mitigate this risk.

# IANA Considerations {#IANA}

This document requests new entries to the "TLS SignatureScheme" registry, according to the procedures in [TLSIANA].

| Value | Description                           | Recommended | Reference      |
| ----- | ------------------------------------- | ----------- | -------------- |
| TBD1  | `fndsa512_rsa2048_pss_sha256`           | N           | This document. |
| TBD2  | `fndsa512_rsa2048_pkcs15_sha256`        | N           | This document. |
| TBD3  | `fndsa512_ecdsa_p256_sha256`            | Y           | This document. |
| TBD4  | `fndsa512_ed25519_sha256`               | N           | This document. |
| TBD5  | `fndsa1024_rsa3072_pss_sha512`          | N           | This document. |
| TBD6  | `fndsa1024_rsa3072_pkcs15_sha512`       | N           | This document. |
| TBD7  | `fndsa1024_ecdsa_p384_sha512`           | N           | This document. |
| TBD8  | `fndsa1024_ecdsa_p521_sha512`           | N           | This document. |
| TBD9  | `fndsa1024_ecdsa_brainpoolP384r1_sha512`| N           | This document. |
| TBD10 | `fndsa1024_ed448_sha256`                | N           | This document. |
{: #tbl-iana title="Additions to TLS SignatureScheme Registry"}



--- back

# Acknowledgments

This document also draws on `draft-reddy-tls-composite-mldsa`. Thanks to the authors of that document.
