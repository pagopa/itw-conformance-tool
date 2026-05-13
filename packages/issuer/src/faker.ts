import { createHash } from 'node:crypto';

import { Faker, it } from '@faker-js/faker';

const DEFAULT_BIRTH_PLACE_CODE = 'H501';
const FISCAL_CODE_MONTH_CODES = 'ABCDEHLMPRST';

const FISCAL_CODE_ODD_MAP: Readonly<Record<string, number>> = {
  '0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
  A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21,
  K: 2, L: 4, M: 18, N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14,
  U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
};

const FISCAL_CODE_EVEN_MAP: Readonly<Record<string, number>> = {
  '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
  A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9,
  K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19,
  U: 20, V: 21, W: 22, X: 23, Y: 24, Z: 25,
};

export interface FakeUser {
  birthDate: string;
  birthPlace: string;
  documentNumber: string;
  familyName: string;
  fiscalCode: string;
  givenName: string;
  id: string;
}

const faker = new Faker({ locale: [it] });

export function generateFakeUser(clientId: string): FakeUser {
  faker.seed(hashToSeed(clientId));

  const id = faker.string.uuid();
  const givenName = faker.person.firstName('male');
  const familyName = faker.person.lastName();
  const birthDate = faker.date.birthdate().toISOString().slice(0, 10);
  const birthPlace = 'Roma (RM)';
  const documentNumber = faker.string.alphanumeric({
    casing: 'upper',
    length: { max: 18, min: 18 },
  });

  return {
    birthDate,
    birthPlace,
    documentNumber,
    familyName,
    fiscalCode: generateFiscalCode({ birthDate, familyName, givenName }),
    givenName,
    id,
  };
}

export function generateFiscalCode({
  birthDate,
  birthPlaceCode = DEFAULT_BIRTH_PLACE_CODE,
  familyName,
  givenName,
}: Readonly<{
  birthDate: string;
  birthPlaceCode?: string;
  familyName: string;
  givenName: string;
}>): string {
  const date = new Date(`${birthDate}T00:00:00.000Z`);
  const year = date.getUTCFullYear().toString().slice(-2);
  const month = FISCAL_CODE_MONTH_CODES[date.getUTCMonth()];
  const day = date.getUTCDate().toString().padStart(2, '0');

  const partialFiscalCode = [
    encodeSurname(familyName),
    encodeName(givenName),
    year,
    month,
    day,
    birthPlaceCode.toUpperCase(),
  ].join('');

  return `${partialFiscalCode}${computeControlCharacter(partialFiscalCode)}`;
}

function hashToSeed(value: string): number {
  const hash = createHash('sha256').update(value).digest();
  return hash.readUInt32BE(0);
}

function encodeSurname(value: string): string {
  return encodeNameParts(value);
}

function encodeName(value: string): string {
  const consonants = extractCharacters(value, 'BCDFGHJKLMNPQRSTVWXYZ');
  if (consonants.length >= 4) {
    return `${consonants[0]}${consonants[2]}${consonants[3]}`;
  }
  return encodeNameParts(value);
}

function encodeNameParts(value: string): string {
  const consonants = extractCharacters(value, 'BCDFGHJKLMNPQRSTVWXYZ');
  const vowels = extractCharacters(value, 'AEIOU');
  return `${consonants}${vowels}XXX`.slice(0, 3);
}

function extractCharacters(value: string, allowed: string): string {
  return normalizeLetters(value)
    .split('')
    .filter((character) => allowed.includes(character))
    .join('');
}

function normalizeLetters(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .replace(/[^A-Za-z]/g, '')
    .toUpperCase();
}

function computeControlCharacter(value: string): string {
  const checksum = value.split('').reduce((total, character, index) => {
    const map = index % 2 === 0 ? FISCAL_CODE_ODD_MAP : FISCAL_CODE_EVEN_MAP;
    return total + (map[character] ?? 0);
  }, 0);
  return String.fromCharCode('A'.charCodeAt(0) + (checksum % 26));
}
