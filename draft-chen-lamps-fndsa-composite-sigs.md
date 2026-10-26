---
stand_alone: true
ipr: trust200902
cat: std
submissiontype: IETF
area: Security
wg: LAMPS

docname: draft-chen-lamps-fndsa-composite-sigs-00

title: Composite FN-DSA for use in X.509 Public Key Infrastructure
abbrev: Composite FN-DSA
lang: en
kw:
  - Post-Quantum
  - PQC
  - Composite Signature
  - Hybrid Signature
  - X.509
  - PKIX
  - FN-DSA
  - Falcon

author:
- name: Meiling Chen
  org: China Mobile
  city: BeiJing
  country: China
  email: chenmeiling@chinamobile.com
- name: Mengyuan Zhang
  org: China Mobile
  city: BeiJing
  country: China
  email: zhangmengyuanwl@chinamobile.com
- name: Xueyan Song
  org: ZTE Corp.
  email: song.xueyan2@zte.com.cn

normative:
  RFC2119:
  RFC8174:
  RFC5280:
  RFC8017:
  RFC8032:
  I-D.turner-lamps-fn-dsa-certificates:
  FIPS206:
    target: https://www.nist.gov/news-
              events/news/2024/08/nist-releases-first-3-finalized-post-
              quantum-encryption-standards
    title: FIPS 206, Fast-Fourier-Transform-based Digital Signature Algorithm
    author:
      - org: National Institute of Standards and Technology (NIST)


--- abstract

To facilitate a robust and secure transition to post-quantum cryptography, this document defines a method for creating composite signature algorithms by combining the Fast-Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm (FN-DSA) with modern classical signature algorithms. These composite algorithms are treated as new, atomic primitives.

This document specifies algorithm identifiers, public key structures, and signature formats for using these composite algorithms within the Internet X.509 Public Key Infrastructure. The methodology is designed to align with modern cryptographic practices, including a principle of strict security level alignment, ensuring a consistent and predictable security posture for all defined algorithms.

--- middle

## 1. Introduction

The Fast-Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm (FN-DSA) [FIPS206], formerly known as Falcon, is a post-quantum signature scheme standardized by the U.S. National Institute of Standards and Technology (NIST). The conventions for using standalone FN-DSA in X.509 certificates are specified in [I-D.turner-lamps-fn-dsa-certificates].

During the transition to post-quantum cryptography, regulatory guidance and organizational security policies may call for post-quantum/traditional (PQ/T) hybrid signatures [RFC9794]. Combining FN-DSA with a traditional signature algorithm can support these requirements while providing protection against quantum computing threats and potential unforeseen weaknesses in FN-DSA.

To support interoperable deployment in existing public key infrastructures, this document specifies a set of composite signature algorithms that combine FN-DSA with selected traditional signature algorithms to ensure that the overall security is at least as strong as that of the stronger component. Each composite algorithm presents a single public key and signature value to applications and is used as a single signature algorithm. The combinations use the pure variant of FN-DSA and follow a **Strict Security Level Alignment** policy, under which each FN-DSA parameter set is paired with a traditional algorithm and parameter set of a corresponding NIST security level. 

To enable interoperable use of these algorithms in X.509 certificates and CRLs [RFC5280], this document specifies the encodings for composite public keys and signatures, assigns Object Identifiers (OIDs) to the composite algorithms, and defines the associated PKI conventions.


## 2. Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

Readers are expected to be familiar with the terms and concepts described in X.509 [RFC5280] and FN-DSA [FIPS206]. This document follows the terminology for post-quantum/traditional (PQ/T) hybrid schemes defined in [RFC9794] and uses the following terms:

- **Composite FN-DSA:** A PQ/T hybrid composite signature scheme that combines FN-DSA with a traditional signature algorithm and exposes the combination through a single signature-scheme interface.
- **Composite Signature:** A signature value produced by a Composite FN-DSA scheme, incorporating an FN-DSA signature value and a traditional signature value.
- **Composite Public Key:** A public key of a Composite FN-DSA scheme, incorporating an FN-DSA public key and the corresponding traditional public key.
- **Security Level:** A NIST classification of post-quantum cryptographic security based on the computational resources required to attack specified reference primitives.
- **Classical Security Strength:** An estimate, expressed in bits, of the computational effort required to break a cryptographic algorithm using classical computing resources.

## 3. Composite Signature Algorithms and Security Levels 
This document standardizes algorithms for two distinct security targets:

*   **Level 1 (128-bit security):** For broad, general-purpose use.
*   **Level 5 (256-bit security):** For high-security, long-term applications.

The following table summarizes the standardized algorithms and their component alignment.

~~~~
+-----------+---------------------------------+---------------------+
| Security  | Composite Algorithm             | Component Alignment |
| Level     |                                 | (PQC + Traditional) |
+-----------+---------------------------------+---------------------+
|           |                                 |                     |
| Level 1   | fndsa512-ecdsa-p256-sha256      | L1 + 128 bits       |
|           |                                 |                     |
|           | fndsa512-ed25519-sha256         | L1 + ≈128 bits      |
|           |                                 |                     |
|           | fndsa512-rsa3072-pss-sha256     | L1 + 128 bits       |
|           |                                 |                     |
|           | fndsa512-rsa3072-pkcs15-sha256  | L1 + 128 bits       |
|           |                                 |                     |
+-----------+---------------------------------+---------------------+
|           |                                 |                     |
| Level 5   | fndsa1024-ecdsa-p521-sha512     | L5 + 256 bits       |
|           |                                 |                     |
|           | fndsa1024-ed448-sha512          | L5 + 224 bits       |
|           |                                 |                     |
+-----------+---------------------------------+---------------------+

      Table 1: Defined Composite Algorithms
~~~~

Combinations with significant security level mismatches, such as pairing a Level 5 post-quantum algorithm with a Level 2 classical algorithm (e.g., RSA-4096), are explicitly **NOT RECOMMENDED** and are excluded from this standard to maintain a robust security model. For legacy compatibility reasons, other profiles MAY define a composite with `rsa-2048`, but this is discouraged. `fndsa512-rsa3072-pss-sha256` is the RECOMMENDED Level 1 RSA-based composite.


## 4. Algorithm Identifiers and Parameters

Each composite signature algorithm defined in this document is identified by a distinct Object Identifier (OID). These OIDs are used in the algorithm field of the AlgorithmIdentifier structure defined in [RFC5280]:

```
AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

Each composite algorithm OID identifies a fixed combination of component algorithms, component parameters, a pre-hash function (PH), and a domain-separation label.

All FN-DSA components use the pure variant. The pre-hash function listed for each composite algorithm is applied at the composite layer and does not select the pre-hash variant of FN-DSA. Any hashing performed internally by a component signature algorithm remains part of that component algorithm.

The following algorithms and parameters are defined:

- **id-fndsa512-ecdsa-p256-sha256**
    - OID: TBD1
    - Label: COMPSIG-FNDSA512-ECDSA-P256-SHA256
    - Pre-hash function (PH): SHA256
    - FN-DSA parameter set: FN-DSA-512
    - Traditional algorithm: ECDSA
	    - Traditional signature algorithm: ecdsa-with-SHA256
		- Elliptic curve: secp256r1

- **id-fndsa512-ed25519-sha256**
    - OID: TBD2
    - Label: COMPSIG-FNDSA512-ED25519-SHA256
    - Pre-hash function (PH): SHA256
    - FN-DSA parameter set: FN-DSA-512
    - Traditional algorithm: Ed25519
	    - Traditional signature algorithm: id-Ed25519

- **id-fndsa512-rsa3072-pss-sha256**
    - OID: TBD3
    - Label: COMPSIG-FNDSA512-RSA3072-PSS-SHA256
    - Pre-hash function (PH): SHA256
    - FN-DSA parameter set: FN-DSA-512
    - Traditional Algorithm: RSA
	    - Traditional signature algorithm: id-RSASSA-PSS
	    - RSA size: 3072
	    - ==RSASSA-PSS message hash: id-sha256==
	    - ==Mask generation function: MGF1 with SHA-256==
	    - ==Salt length: 32 octets==
	    - ==Trailer field: 1, corresponding to the trailer octet 0xBC==

- **id-fndsa1024-ecdsa-p521-sha512**
    - OID: TBD4
    - Label: COMPSIG-FNDSA1024-ECDSA-P521-SHA512
    - Pre-hash function (PH): SHA-512
    - FN-DSA parameter set: FN-DSA-1024
    - Traditional Algorithm: ECDSA
	    - Traditional Signature Algorithm: ecdsa-with-SHA512
	    - ECDSA curve: secp521r1

- **id-fndsa1024-ed448-sha512**
    - OID: TBD5
    - Label: COMPSIG-FNDSA1024-Ed448-SHA512
    - Pre-hash function (PH): SHA-512
    - FN-DSA parameter set: FN-DSA-1024
    - Traditional Algorithm: Ed448
	    - Traditional signature algorithm: Ed448

Each Label is the ASCII encoding of the exact string listed above, without a terminating NUL octet.

The Ed25519 and Ed448 components MUST use the pure variants defined in [RFC8032]. Ed25519ph, Ed25519ctx, and Ed448ph MUST NOT be used. The Ed448 component MUST use an empty context string.

The RSASSA-PSS component requires additional parameters as defined in [RFC8017]. For id-fndsa512-rsa3072-pss-sha256, these parameters MUST have the following values:

|RSASSA-PSS-params field|Value|
|---|---|
|hashAlgorithm|id-sha256|
|maskGenAlgorithm.algorithm|id-mgf1|
|maskGenAlgorithm.parameters|AlgorithmIdentifier identifying SHA-256|
|saltLength|32|
|trailerField|1|

The `parameters` field of `AlgorithmIdentifier` MUST be absent for all composite algorithm identifiers defined in this section. It MUST NOT contain an ASN.1 `NULL` value. This requirement also applies to composites using RSASSA-PSS: the RSASSA-PSS parameters are fixed by the composite algorithm identifier, and no `RSASSA-PSS-params` structure is carried in the `parameters` field.

The OID values are pending assignment. TBD1 through TBD5 are editorial placeholders and are not valid OID values.



## 5. Composite FN-DSA Signature Scheme

This section specifies the serialization and deserialization of composite keys and signature values, together with the key generation, signature generation, and signature verification operations.

Each operation is instantiated for a composite algorithm identifier defined in Section 4. The identifier determines the FN-DSA parameter set, the traditional signature algorithm and its parameters, the composite-layer pre-hash function PH, and the domain-separation Label. These values are fixed for that identifier and are not independently selectable by the caller.

### 5.1. Serialization and Deserialization

The functions in this section convert component keys and signatures to and from composite octet strings. Each function is instantiated for a composite algorithm identifier defined in Section 4, which determines the component algorithms, parameters, and encodings.

Deserialization returns ERROR if the input is malformed or does not conform to the requirements for the selected composite algorithm. Each component decoder MUST consume its entire assigned input; trailing octets MUST NOT be ignored.

> EDITOR'S NOTE: The FN-DSA seed length, encoding, and key reconstruction procedure are to be confirmed against the finalized [FIPS206]. This note is to be removed when those dependencies are resolved.

#### 5.1.1. Public Keys

The public-key serialization and deserialization functions are:

```
Composite-FN-DSA.SerializePublicKey(pk_fndsa, pk_trad) -> pk
Composite-FN-DSA<OID>.DeserializePublicKey(pk) 
	-> (pk_fndsa, pk_trad) or ERROR
```

`OID` is one of the composite algorithm OIDs defined in Section 4 and determines the component algorithms and parameters.

The serialized public key is:

```
pk = pk_fndsa || pk_trad
```

`pk_fndsa` is the raw FN-DSA public-key encoding specified in [FIPS206], without an ASN.1 wrapper. Its length is 897 octets for FN-DSA-512 and 1793 octets for FN-DSA-1024.

`pk_trad` MUST be encoded as follows:

- **ECDSA P-256:** The 65-octet uncompressed point encoding `0x04 || X || Y`, with each coordinate encoded in 32 octets, as specified in [RFC5480].
- **ECDSA P-521:** The 133-octet uncompressed point encoding `0x04 || X || Y`, with each coordinate encoded in 66 octets, as specified in [RFC5480].
- **Ed25519:** The 32-octet public-key encoding specified in [RFC8032].
- **Ed448:** The 57-octet public-key encoding specified in [RFC8032].
- **RSA-3072:** The DER encoding of the `RSAPublicKey` structure specified in [RFC8017], containing a modulus of exactly 3072 bits and its public exponent.

Compressed and hybrid ECDSA point encodings MUST NOT be used.

Deserialization determines the FN-DSA public-key length `L` from the parameter set identified by `OID` and splits the input as follows:

```
pk_fndsa = pk[0:L]
pk_trad  = pk[L:]
```

The input MUST contain both components. Each component MUST have the required encoding and satisfy the public-key validation requirements of the selected algorithm. 

#### 5.1.2. Private Keys

The private-key serialization and deserialization functions are:

```
Composite-FN-DSA.SerializePrivateKey(seed_fndsa, sk_trad) -> sk
Composite-FN-DSA.DeserializePrivateKey(sk) 
	-> (seed_fndsa, sk_trad)
```

The serialized private key is:

```
sk = seed_fndsa || sk_trad
```

`seed_fndsa` is the 32-octet FN-DSA key-generation seed, included directly without an ASN.1 wrapper.

`sk_trad` MUST be encoded as follows:

- **ECDSA P-256:** The private scalar `d` encoded as a 32-octet unsigned, big-endian integer.
- **ECDSA P-521:** The private scalar `d` encoded as a 66-octet unsigned, big-endian integer.
- **Ed25519:** The 32-octet private-key seed specified in [RFC8032].
- **Ed448:** The 57-octet private-key seed specified in [RFC8032].
- **RSA-3072:** The DER encoding of the two-prime `RSAPrivateKey` structure specified in [RFC8017], with `version` equal to 0 and all CRT fields present.

For ECDSA, leading zero octets needed to obtain the required length MUST be retained, and the scalar MUST satisfy `1 <= d < n`, where `n` is the selected curve's base-point order. No `ECPrivateKey` wrapper is included. For EdDSA, the encoding contains only the seed, without an appended public key or expanded signing representation.

Serialization encodes the component private-key material as specified above and concatenates it in the indicated order.

Deserialization requires an input longer than 32 octets and splits it as follows:

```
seed_fndsa = sk[0:32]
sk_trad    = sk[32:]
```

The traditional component MUST have the required encoding and satisfy the private-key validation requirements of the selected algorithm. 

#### 5.1.3. Signature Values

The signature serialization and deserialization functions are:

```
Composite-FN-DSA.SerializeSignatureValue(sig_fndsa, sig_trad) -> sig
Composite-FN-DSA<OID>.DeserializeSignatureValue(sig) 
	-> (sig_fndsa, sig_trad) or ERROR
```

The serialized signature is:

```
sig = sig_fndsa || sig_trad
```

> EDITOR'S NOTE: This document assumes a fixed-length FN-DSA signature encoding. The encoding and lengths are to be confirmed against the finalized [FIPS206]. This note is to be removed once that specification is finalized and the corresponding definitions in this document have been updated.

`sig_fndsa` MUST use the signature encoding specified in [FIPS206] for the selected parameter set, including any required padding. Its encoded length MUST be between 1 and 65535 octets and MUST satisfy any tighter limits imposed by that specification.

`sk_trad` MUST be encoded as follows:

- **ECDSA:** The DER encoding of `Ecdsa-Sig-Value` specified in [RFC3279], containing the signature integers `r` and `s`.
- **Ed25519:** The 64-octet signature encoding specified in [RFC8032].
- **Ed448:** The 114-octet signature encoding specified in [RFC8032].
- **RSASSA-PSS with RSA-3072:** The 384-octet signature encoding specified in [RFC8017], retaining any leading zero octets.

Deserialization determines the FN-DSA signature length `L` from the parameter set identified by `OID` and splits the input as follows:

```
sig_fndsa = sig[:L]
sig_trad  = sig[L:]
```

Each resulting component MUST have the required encoding. Fixed-length traditional signatures MUST have exactly the specified length.

Successful deserialization does not establish signature validity. Both component signatures MUST subsequently be verified as specified in Section 5.4.

### 5.2. Key Generation

The `KeyGen()` function for a given Composite FN-DSA algorithm represented by `OID` is defined as:

```
Composite-ML-DSA<OID>.KeyGen() -> (pk, sk) or ERROR
```

`OID` MUST identify one of the composite algorithms defined in Section 4.

The operation proceeds as follows:

1. ==Generate an FN-DSA key pair== `pk_fndsa` for the selected parameter set according to [FIPS206], retaining the key-generation seed required by Section 5.1.2.（因为标准没出无法展开写）
2. ==Generate a traditional key pair== `pk_trad` according to the selected traditional signature algorithm and its parameter requirements.
3. Compute the composite public key and private key:
	```
	pk = SerializePublicKey(alg, pk_fndsa, pk_trad)
	sk = SerializePrivateKey(alg, seed_fndsa, sk_trad)
	```
4. Return `(pk, sk)`. If either component key generation or serialization fails, return `ERROR` and do not return a partial composite key pair.

### 5.3. Signature Generation
The composite signature-generation operation accepts a message `M`, a composite private key `sk`, and an optional context string `ctx`. If no context is supplied, `ctx` is the empty octet string.

The `Sign()` function for a given Composite FN-DSA algorithm represented by `OID` is defined as:

```
Composite-FN-DSA<OID>.Sign(sk, M, ctx) -> sig
```

The message and context are octet strings. Their interpretation by an application is outside the scope of this section. The context string MUST be at most 255 octets long. An implementation MUST reject a longer context; it MUST NOT truncate it.

The operation proceeds as follows:

1. Compute the Message representative `M'`:
	```
	M' = Prefix || Label || len(ctx) || ctx || PH(M)
	```
2. Deserialize the input composite private key:
    ```
    (seed_fndsa, sk_trad) = DeserializePrivateKey(sk)
    ```
3. ==Reconstruct the FN-DSA signing key== `sk_fndsa` from `seed_fndsa`.
4. Generate the two component signatures independently over the same `M'` according to their algorithm specifications:
    ```
    sig_fndsa = FNDSA.Sign(sk_fndsa, M', fndsa_ctx="")
    sig_trad = Trad.Sign(sk_trad, M')
    ```
5. Serialize the component signatures:
    ```
    sig = SerializeSignatureValue(alg, sig_fndsa, sig_trad)
    ```
6. Return `sig`. If either component signing operation or serialization fails, return `ERROR`. A partial composite signature MUST NOT be returned.

The fields used to construct `M'` in Step 1 are defined as follows:

- `Prefix` is the ASCII encoding of the exact string `CompositeFNDSASignatures2026`.
- `Label` is the ASCII-encoded domain-separation label assigned to each `OID` in Section 4.
- `len(ctx)` is the length of `ctx` in octets, encoded as a single unsigned octet.
- `ctx` is the context string supplied to the composite signature-generation operation to bind the signature to an application context.
- `PH(M)` is the result of applying the pre-hash function assigned to `OID` in Section 4 to the complete message `M`.

The component signing operations receive the complete `M'`. The composite-layer pre-hash does not replace hashing performed by a component signature algorithm.

All randomness required by component signature generation MUST be generated and used according to the respective component specifications. Random values, including signature nonces and salts, MUST NOT be reused across component algorithms.

### 5.4. Signature Verification

The composite signature-verification operation accepts a message `M`, a composite public key `pk`, a composite signature `sig`, and an optional context string `ctx`. If no context is supplied, `ctx` is the empty octet string.

The `Verify()` function for a given Composite FN-DSA algorithm represented by `OID` is defined as:

```
Composite-FN-DSA<OID>.Verify(pk, M, sig, ctx) -> VALID or INVALID
```

The component algorithms and parameters are determined by `OID` as specified in Section 4. The verifier MUST use the same context octets as the signer; the context is not recovered from the signature.

The operation proceeds as follows:

1. If `len(ctx) > 255`, return `INVALID`.
2. Deserialize the input composite public key and signature:
    ```
    (pk_fndsa, pk_trad) = Composite-FN-DSA<OID>.DeserializePublicKey(pk)
    (sig_fndsa, sig_trad) = 
	    Composite-FN-DSA<OID>.DeserializeSignatureValue(sig)
    ```
    If either deserialization operation returns `ERROR`, return `INVALID`.
3. Reconstruct the message representative `M'` using the construction and field definitions specified in Section 5.3:
    ```
    M' = Prefix || Label || len(ctx) || ctx || PH(M)
    ```
4. Verify the two component signatures independently over the same `M'` according to their algorithm specifications:
    ```
    valid_fndsa = FNDSA.Verify(pk_fndsa, M', sig_fndsa, fndsa_ctx="")
    valid_trad = Trad.Verify(pk_trad, M', sig_trad)
    ```
5. Return `VALID` if and only if both component verifications succeed. Otherwise, return `INVALID`. Any component processing error MUST result in `INVALID`.

An implementation MAY return `INVALID` as soon as a failure is established, without performing the remaining operations.


## 6. PKIX Profile 

This section provides a profile for the use of composite FN-DSA signature algorithms in the Internet X.509 PKI [RFC5280].

### 6.1. Certificate `signatureAlgorithm` Field
The `signatureAlgorithm` field in a certificate that is signed with a composite algorithm MUST contain the OID of the composite algorithm used.

### 6.2. Subject Public Key Info
The `subjectPublicKeyInfo` field in a certificate containing a composite public key MUST be populated as follows:
*   The `algorithm` field MUST contain the OID of the composite algorithm.
*   The `subjectPublicKey` field MUST contain the `BIT STRING` representation of the `CompositePublicKey` as defined in Section 5.1.

### 6.3. Key Usage
The `keyUsage` extension in a certificate containing a composite public key SHOULD be marked as `critical`. The `digitalSignature` and/or `nonRepudiation` bits MUST be set. If the key is used to sign certificates, the `keyCertSign` bit MUST be set. If it is used to sign CRLs, the `cRLSign` bit MUST be set.


## 7. IANA Considerations
This document requests the assignment of five Object Identifiers from a suitable OID arc for the composite signature algorithms defined in Section 4. These OIDs identify the new signature algorithms and are intended for use in X.509 certificates and other cryptographic protocols.

## 8. Security Considerations
The primary security goal of this specification is to provide **hybrid security**. A composite signature's security is intended to be at least as high as the security of its strongest component. An attacker must break *both* the FN-DSA component and the classical component to forge a composite signature.

**Security Level Alignment**: This specification mandates the pairing of algorithms with matching or near-matching NIST security levels. This provides a clear and predictable security posture for each composite algorithm, preventing "unbalanced" pairings where one component is significantly weaker than the other. Implementers SHOULD follow this principle when considering extensions.

**Domain Separation**: The domain separation mechanism described in Section 5.2.1 is critical. It ensures that a signature component created for this composite scheme cannot be misinterpreted as a valid standalone signature in another context. Implementers MUST follow the message preparation steps exactly.

**Modern Algorithm Preference**: This specification RECOMMENDS the use of modern elliptic curve algorithms (ECDSA, EdDSA) over RSA. This is due to their superior performance, smaller key and signature sizes, and better resistance to certain types of implementation errors.

**Implementation Security**: All security considerations from the component algorithm specifications ([FIPS206], [RFC8017], [RFC8032], etc.) apply. Implementations must protect against side-channel attacks for all component algorithms.
