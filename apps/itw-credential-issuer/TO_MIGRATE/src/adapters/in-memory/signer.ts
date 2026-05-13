import { JwksRepository } from '../../domain/signer';
import { ECKey, ECPrivateKeyWithKid } from '../../domain/z-jwk';

const extractKeys = (jwk: readonly ECPrivateKeyWithKid[]) => {
  if (jwk.length === 0) {
    throw new Error('Unable to find valid JWK key pair');
  }

  //Extracting the d entry because typescript doesn't
  //remove entries not declared in the type when casting,
  //so even if the type is of a public key the key will
  //still keep the private part
  const { d, ...publicKey } = jwk[0];
  void d;

  const jwkKeyPair = {
    private: { ...jwk[0], kty: 'EC' } as {
      kid: string;
      readonly kty: 'EC';
    } & ECPrivateKeyWithKid,
    public: publicKey as { kid: string; readonly kty: 'EC' } & ECKey
  };

  return jwkKeyPair;
};

export const makeJwksRepository = (
  sigJwks: readonly ECPrivateKeyWithKid[],
  encJwks: readonly ECPrivateKeyWithKid[],
  iacaX509: string
): JwksRepository => ({
  getEncrypt: () => extractKeys(encJwks),
  getSign: () => extractKeys(sigJwks),
  iacaX509: () => iacaX509
});
