import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createMdocCredential } from '../issue';

const { coseKeyFromJwk, deviceKeyFromJwk, issuerAddIssuerNamespace, issuerSign } = vi.hoisted(() => ({
  coseKeyFromJwk: vi.fn(),
  deviceKeyFromJwk: vi.fn(),
  issuerAddIssuerNamespace: vi.fn(),
  issuerSign: vi.fn()
}));

vi.mock('@owf/mdoc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@owf/mdoc')>();

  return {
    ...actual,
    CoseKey: {
      ...actual.CoseKey,
      fromJwk: coseKeyFromJwk
    },
    DeviceKey: {
      ...actual.DeviceKey,
      fromJwk: deviceKeyFromJwk
    },
    Issuer: vi.fn().mockImplementation(() => ({
      addIssuerNamespace: issuerAddIssuerNamespace,
      sign: issuerSign
    }))
  };
});

vi.mock('../utils', () => ({
  pemToDer: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
  stripKid: vi.fn((jwk) => {
    const { kid, ...jwkWithoutKid } = jwk;
    void kid;
    return jwkWithoutKid;
  })
}));

describe('createMdocCredential()', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    issuerAddIssuerNamespace.mockReturnValue({
      sign: issuerSign
    });
    issuerSign.mockResolvedValue({
      encodedForOid4Vci: 'encoded-mdoc'
    });
    coseKeyFromJwk.mockImplementation((jwk) => ({
      jwk
    }));
    deviceKeyFromJwk.mockImplementation((jwk) => ({
      jwk
    }));
  });

  it('builds and signs an OWF issuer-signed credential', async () => {
    const credential = await createMdocCredential(
      {
        docType: 'org.iso.18013.5.1.mDL',
        namespaces: {
          'org.iso.18013.5.1': { given_name: 'Mario' },
          'org.iso.18013.5.1.aamva': { donor: true }
        },
        validityInfo: {
          signed: new Date('2026-01-01'),
          validFrom: new Date('2026-01-01'),
          validUntil: new Date('2028-09-30')
        }
      },
      {
        getEncrypt: vi.fn(),
        getSign: vi.fn().mockReturnValue({
          private: {
            crv: 'P-256',
            d: 'issuer-d',
            kid: 'issuer-kid',
            kty: 'EC',
            x: 'issuer-x',
            y: 'issuer-y'
          }
        }),
        iacaX509: vi.fn().mockReturnValue('mock-certificate')
      } as never,
      {
        crv: 'P-256',
        kid: 'holder-kid',
        kty: 'EC',
        x: 'holder-x',
        y: 'holder-y'
      }
    );

    expect(credential).toBe('encoded-mdoc');
    expect(issuerAddIssuerNamespace).toHaveBeenCalledWith('org.iso.18013.5.1', {
      given_name: 'Mario'
    });
    expect(issuerAddIssuerNamespace).toHaveBeenCalledWith('org.iso.18013.5.1.aamva', {
      donor: true
    });
    expect(issuerAddIssuerNamespace).toHaveBeenCalledTimes(2);
    expect(coseKeyFromJwk).toHaveBeenCalledTimes(1);
    expect(deviceKeyFromJwk).toHaveBeenCalledTimes(1);
    expect(issuerSign).toHaveBeenCalledWith(
      expect.objectContaining({
        certificates: [new Uint8Array([1, 2, 3])],
        digestAlgorithm: 'SHA-256'
      })
    );
  });
});
