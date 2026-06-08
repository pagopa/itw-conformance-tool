import { describe, expect, it } from 'vitest';

import { getRequirements } from '../utils/requirement-mapper.js';

describe('getRequirements', () => {
  describe('ISSUANCE phase', () => {
    it('returns the PAR requirement for PAR:ISSUANCE', () => {
      const reqs = getRequirements('PAR', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.2.1');
    });

    it('returns the AUTHORIZE requirement for AUTHORIZE:ISSUANCE', () => {
      const reqs = getRequirements('AUTHORIZE', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.2.2');
    });

    it('returns the PRESENTATION_RESPONSE requirement for PRESENTATION_RESPONSE:ISSUANCE', () => {
      const reqs = getRequirements('PRESENTATION_RESPONSE', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.2.3');
    });

    it('returns the AUTHORIZATION_CODE requirement for AUTHORIZATION_CODE:ISSUANCE', () => {
      const reqs = getRequirements('AUTHORIZATION_CODE', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.2.4');
    });

    it('returns the TOKEN requirement for TOKEN:ISSUANCE', () => {
      const reqs = getRequirements('TOKEN', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.3.2');
    });

    it('returns the NONCE requirement for NONCE:ISSUANCE', () => {
      const reqs = getRequirements('NONCE', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.3.3');
    });

    it('returns the CREDENTIAL requirement for CREDENTIAL:ISSUANCE', () => {
      const reqs = getRequirements('CREDENTIAL', 'ISSUANCE');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§4.3.4');
    });
  });

  describe('PRESENTATION phase', () => {
    it('returns the AUTHORIZE requirement for AUTHORIZE:PRESENTATION', () => {
      const reqs = getRequirements('AUTHORIZE', 'PRESENTATION');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§5.2.1');
    });

    it('returns the PRESENTATION_RESPONSE requirement for PRESENTATION_RESPONSE:PRESENTATION', () => {
      const reqs = getRequirements('PRESENTATION_RESPONSE', 'PRESENTATION');
      expect(reqs).toHaveLength(1);
      expect(reqs[0]?.requirementId).toBe('IT-WALLET-1.4-§5.2.2');
    });
  });

  describe('undefined combinations', () => {
    it('returns an empty array for PAR:PRESENTATION (not part of RP flow)', () => {
      expect(getRequirements('PAR', 'PRESENTATION')).toEqual([]);
    });

    it('returns an empty array for TOKEN:PRESENTATION (not part of RP flow)', () => {
      expect(getRequirements('TOKEN', 'PRESENTATION')).toEqual([]);
    });

    it('returns an empty array for NONCE:PRESENTATION (not part of RP flow)', () => {
      expect(getRequirements('NONCE', 'PRESENTATION')).toEqual([]);
    });

    it('returns an empty array for CREDENTIAL:PRESENTATION (not part of RP flow)', () => {
      expect(getRequirements('CREDENTIAL', 'PRESENTATION')).toEqual([]);
    });

    it('returns an empty array for AUTHORIZATION_CODE:PRESENTATION (not part of RP flow)', () => {
      expect(getRequirements('AUTHORIZATION_CODE', 'PRESENTATION')).toEqual([]);
    });
  });

  describe('result shape', () => {
    it('every returned requirement has a non-empty requirementId and description', () => {
      const steps = [
        'PAR',
        'AUTHORIZE',
        'PRESENTATION_RESPONSE',
        'AUTHORIZATION_CODE',
        'TOKEN',
        'NONCE',
        'CREDENTIAL'
      ] as const;
      const phases = ['ISSUANCE', 'PRESENTATION'] as const;

      for (const step of steps) {
        for (const phase of phases) {
          for (const req of getRequirements(step, phase)) {
            expect(req.requirementId.length).toBeGreaterThan(0);
            expect(req.description.length).toBeGreaterThan(0);
          }
        }
      }
    });
  });
});
