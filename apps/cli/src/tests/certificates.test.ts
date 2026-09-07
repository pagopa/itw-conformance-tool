import { X509Certificate } from '@peculiar/x509';
import { describe, expect, it } from 'vitest';

import {
  createRelyingPartyFederationCertificateFromJwk,
  createRelyingPartyIntermediateCertificateFromJwk,
  createSelfSignedCertificateFromJwk,
  createSelfSignedEncryptionCertificateFromJwk,
  createTrustAnchorCertificateFromJwk,
  selectEcdhEsEncryptionJwk,
  selectEs256SigningJwk
} from '../utils/certificates.js';
import {
  createRelyingPartyFederationKey,
  createRelyingPartyIntermediateKey,
  createRelyingPartyPrivateKeys,
  createTrustAnchorFederationKey
} from '../utils/crypto.js';

const RELYING_PARTY_URL = 'https://127.0.0.1:3002';
const TRUST_ANCHOR_HOSTNAME = '127.0.0.1';

/** Key usage bit positions, as they appear in an X.509 KeyUsage BIT STRING. */
const KEY_USAGE = {
  cRLSign: 6,
  digitalSignature: 0,
  keyAgreement: 4,
  keyCertSign: 5
} as const;

function keyUsages(certificatePem: string): Set<number> {
  const extension = new X509Certificate(certificatePem).getExtension('2.5.29.15');
  if (!extension) throw new Error('certificate carries no KeyUsage extension');

  // The extension value is a BIT STRING: one unused-bit count byte, then the
  // bits themselves, most significant bit first.
  const [unusedBits, ...bytes] = new Uint8Array(extension.value.slice(2));
  void unusedBits;

  const usages = new Set<number>();
  bytes.forEach((byte, byteIndex) => {
    for (let bit = 0; bit < 8; bit += 1) {
      if (byte & (0x80 >> bit)) usages.add(byteIndex * 8 + bit);
    }
  });

  return usages;
}

function isCertificateAuthority(certificatePem: string): boolean {
  const extension = new X509Certificate(certificatePem).getExtension('2.5.29.19');
  if (!extension) return false;

  // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... } — cA is
  // present only when true, encoded as a DER BOOLEAN (tag 0x01).
  return new Uint8Array(extension.value).includes(0x01);
}

/** Asserts that `certificate` was issued by `issuer` — the binding an `x5c`
 * chain depends on, checked cryptographically rather than by subject name. */
async function isSignedBy(certificatePem: string, issuerPem: string): Promise<boolean> {
  return new X509Certificate(certificatePem).verify({
    publicKey: await new X509Certificate(issuerPem).publicKey.export()
  });
}

describe('Trust Anchor federation certificate', () => {
  it('is a CA allowed to sign the subordinate certificates beneath it', async () => {
    // It is the root of every federation x5c chain. Issued as a leaf — which it
    // was, with an encipherOnly key usage — the issuer and Wallet Provider
    // chains hanging off it failed path validation outright.
    const certificate = await createTrustAnchorCertificateFromJwk(
      createTrustAnchorFederationKey(),
      TRUST_ANCHOR_HOSTNAME
    );

    expect(isCertificateAuthority(certificate)).toBe(true);
    expect(keyUsages(certificate)).toContain(KEY_USAGE.keyCertSign);
    expect(keyUsages(certificate)).toContain(KEY_USAGE.cRLSign);
  });

  it('outlives the subordinate CA certificates it signs', async () => {
    const trustAnchorKey = createTrustAnchorFederationKey();
    const trustAnchorCertificate = await createTrustAnchorCertificateFromJwk(trustAnchorKey, TRUST_ANCHOR_HOSTNAME);
    const intermediate = await createRelyingPartyIntermediateCertificateFromJwk(
      createRelyingPartyIntermediateKey(),
      trustAnchorKey,
      trustAnchorCertificate
    );

    // A root expiring before its own intermediate would invalidate chains that
    // are otherwise still current.
    expect(new X509Certificate(trustAnchorCertificate).notAfter.getTime()).toBeGreaterThanOrEqual(
      new X509Certificate(intermediate).notAfter.getTime()
    );
  });
});

describe('Relying Party federation certificate chain', () => {
  it('chains the federation key up to the Trust Anchor', async () => {
    const trustAnchorKey = createTrustAnchorFederationKey();
    const trustAnchorCertificate = await createTrustAnchorCertificateFromJwk(trustAnchorKey, TRUST_ANCHOR_HOSTNAME);
    const intermediateKey = createRelyingPartyIntermediateKey();
    const intermediateCertificate = await createRelyingPartyIntermediateCertificateFromJwk(
      intermediateKey,
      trustAnchorKey,
      trustAnchorCertificate
    );
    const federationCertificate = await createRelyingPartyFederationCertificateFromJwk(
      createRelyingPartyFederationKey(),
      intermediateKey,
      intermediateCertificate,
      RELYING_PARTY_URL
    );

    // The two links the published `[leaf, intermediate]` x5c asks a verifier to
    // walk, with the Trust Anchor root supplied out of band.
    await expect(isSignedBy(federationCertificate, intermediateCertificate)).resolves.toBe(true);
    await expect(isSignedBy(intermediateCertificate, trustAnchorCertificate)).resolves.toBe(true);
  });
});

describe('Relying Party application certificates', () => {
  it('keeps the application keys out of the federation trust chain', async () => {
    const applicationJwks = createRelyingPartyPrivateKeys();
    const signingCertificate = await createSelfSignedCertificateFromJwk(selectEs256SigningJwk(applicationJwks), {
      commonName: TRUST_ANCHOR_HOSTNAME
    });
    const encryptionCertificate = await createSelfSignedEncryptionCertificateFromJwk(
      selectEcdhEsEncryptionJwk(applicationJwks),
      { commonName: TRUST_ANCHOR_HOSTNAME }
    );

    // Self-signed on purpose: a wallet resolving the Relying Party through
    // `x509_hash` is deliberately not being pointed at the Trust Anchor.
    await expect(isSignedBy(signingCertificate, signingCertificate)).resolves.toBe(true);
    await expect(isSignedBy(encryptionCertificate, encryptionCertificate)).resolves.toBe(true);
  });

  it('certifies the encryption key for key agreement', async () => {
    const encryptionCertificate = await createSelfSignedEncryptionCertificateFromJwk(
      selectEcdhEsEncryptionJwk(createRelyingPartyPrivateKeys()),
      { commonName: TRUST_ANCHOR_HOSTNAME }
    );

    // keyAgreement is what the key is for; digitalSignature is what makes the
    // self-signature it carries consistent with its own declared usage.
    expect(keyUsages(encryptionCertificate)).toContain(KEY_USAGE.keyAgreement);
    expect(keyUsages(encryptionCertificate)).toContain(KEY_USAGE.digitalSignature);
    expect(isCertificateAuthority(encryptionCertificate)).toBe(false);
  });
});

describe('Relying Party key roles', () => {
  it('separates the application keys from the federation key', () => {
    const applicationJwks = createRelyingPartyPrivateKeys();
    const federationKey = createRelyingPartyFederationKey();

    // The federation key is not merely a different array entry: it is not in
    // this JWKS at all, so no selector can reach it by position.
    expect(applicationJwks.keys).toHaveLength(2);
    expect(applicationJwks.keys.map((key) => key.kid)).not.toContain(federationKey.kid);

    const signing = selectEs256SigningJwk(applicationJwks);
    const encryption = selectEcdhEsEncryptionJwk(applicationJwks);
    expect(new Set([signing.kid, encryption.kid, federationKey.kid]).size).toBe(3);
  });

  it('refuses to pick a signing key when the role is ambiguous', () => {
    const applicationJwks = createRelyingPartyPrivateKeys();
    const withSecondSigningKey = { keys: [...applicationJwks.keys, createRelyingPartyFederationKey()] };

    // Two signing keys in one JWKS is the layout this split removed: rather than
    // silently certifying whichever came first, selection fails.
    expect(() => selectEs256SigningJwk(withSecondSigningKey)).toThrow(/Multiple private ES256 signing keys/);
  });
});
