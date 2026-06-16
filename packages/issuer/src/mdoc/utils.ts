import { sha256 } from '@itw-conformance-tool/crypto';
import { DataItem, cborEncode } from '@owf/mdoc';
import { X509Certificate } from '@peculiar/x509';
import { calculateJwkThumbprint } from 'jose';

import type { JwkPrivateKey, JwkPublicKey } from '../z-jwk.js';

export const stripKid = <T extends JwkPrivateKey | JwkPublicKey>(jwk: T): Omit<T, 'kid'> => {
  const { kid, ...jwkWithoutKid } = jwk;
  void kid;

  return jwkWithoutKid;
};

export const pemToDer = (certificate: string): Uint8Array => new Uint8Array(new X509Certificate(certificate).rawData);

interface CreateOid4VpSessionTranscriptOptions {
  clientId: string;
  handoverUri: string;
  nonce: string;
  verifierEncryptionPublicJwk?: JwkPublicKey;
}

const getJwkThumbprint = async (jwk?: JwkPublicKey): Promise<Uint8Array | null> => {
  if (!jwk) {
    return null;
  }

  const thumbprint = await calculateJwkThumbprint(jwk);
  return new Uint8Array(Buffer.from(thumbprint, 'base64url'));
};

export const createOid4VpSessionTranscript = async ({
  clientId,
  handoverUri,
  nonce,
  verifierEncryptionPublicJwk
}: CreateOid4VpSessionTranscriptOptions): Promise<Uint8Array> => {
  const handoverInfo = [clientId, nonce, await getJwkThumbprint(verifierEncryptionPublicJwk), handoverUri];
  const handover = ['OpenID4VPHandover', sha256(cborEncode(DataItem.fromData(handoverInfo)))];

  return cborEncode(DataItem.fromData([null, null, handover]));
};
