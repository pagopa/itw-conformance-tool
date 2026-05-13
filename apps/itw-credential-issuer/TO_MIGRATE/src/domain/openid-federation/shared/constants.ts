import { config } from '@/app/config';
import { toPublicJwk } from '@/domain/crypto';

export const pidIdentification = 'PersonIdentificationData'; //TODO urn:eu.europa.ec.eudi:pid:1';

export const verifierPublicKeys = toPublicJwk([...config.signer.jwks, ...config.encrypter.jwks]);
