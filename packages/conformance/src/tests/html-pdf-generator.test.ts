import { describe, expect, it, vi } from 'vitest';

import { generateRenderedReport, renderHtmlReport, renderPdfReport } from '../reporters/html-pdf-generator.js';

import type { JsonReporterResult } from '../reporters/json-reporter.js';

vi.mock('puppeteer', () => ({
  default: {
    launch: vi.fn(async () => ({
      newPage: vi.fn(async () => ({
        setContent: vi.fn(),
        pdf: vi.fn(async () => new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34]))
      })),
      close: vi.fn()
    }))
  }
}));

function makeJsonReporter(): JsonReporterResult {
  return {
    coverageMap: {},
    meta: {
      closedAt: '2026-06-12T12:05:00.000Z',
      runId: '550e8400-e29b-41d4-a716-446655440000',
      startedAt: '2026-06-12T12:00:00.000Z',
      status: 'FAILED'
    },
    numFailedTestSuites: 1,
    numFailedTests: 1,
    numPassedTestSuites: 1,
    numPassedTests: 1,
    numPendingTestSuites: 0,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTestSuites: 2,
    numTotalTests: 2,
    startTime: Date.parse('2026-06-12T12:00:00.000Z'),
    success: false,
    testResults: [
      {
        assertionResults: [
          {
            ancestorTitles: ['Issuance Flow', 'PAR'],
            duration: 0,
            failureMessages: [],
            fullName: 'Issuance Flow PAR request contains a valid Wallet Attestation JWT',
            location: { column: 1, line: 1 },
            meta: {
              phase: 'ISSUANCE',
              requirementId: 'IT-WALLET-1.4-§4.2.1',
              result: 'PASS',
              step: 'PAR',
              timestamp: '2026-06-12T12:00:05.000Z'
            },
            status: 'passed',
            title: 'request contains a valid Wallet Attestation JWT'
          }
        ],
        endTime: Date.parse('2026-06-12T12:00:05.000Z'),
        message: '',
        name: 'PAR',
        startTime: Date.parse('2026-06-12T12:00:05.000Z'),
        status: 'passed'
      },
      {
        assertionResults: [
          {
            ancestorTitles: ['Issuance Flow', 'TOKEN'],
            duration: 0,
            failureMessages: ['invalid dpop', 'HTTP 400'],
            fullName: 'Issuance Flow TOKEN request includes a valid DPoP proof',
            location: { column: 1, line: 1 },
            meta: {
              httpStatus: 400,
              phase: 'ISSUANCE',
              requirementId: 'IT-WALLET-1.4-§4.3.2',
              result: 'FAIL',
              step: 'TOKEN',
              timestamp: '2026-06-12T12:00:15.000Z'
            },
            status: 'failed',
            title: 'request includes a valid DPoP proof'
          }
        ],
        endTime: Date.parse('2026-06-12T12:00:15.000Z'),
        message: '',
        name: 'TOKEN',
        startTime: Date.parse('2026-06-12T12:00:15.000Z'),
        status: 'failed'
      }
    ]
  };
}

describe('html-pdf-generator', () => {
  it('renders a populated HTML report from JsonReporter data', () => {
    const html = renderHtmlReport(makeJsonReporter(), { generatedAt: new Date('2026-06-12T12:10:00.000Z') });

    expect(html).toContain('<!doctype html>');
    expect(html).toContain('Conformance Report - 550e8400-e29b-41d4-a716-446655440000');
    expect(html).toContain('IT-WALLET-1.4-§4.3.2');
    expect(html).toContain('invalid dpop');
  });

  it('renders a binary PDF payload', async () => {
    const pdf = await renderPdfReport(makeJsonReporter(), { generatedAt: new Date('2026-06-12T12:10:00.000Z') });

    expect(pdf).toBeInstanceOf(Uint8Array);
    expect(pdf.length).toBeGreaterThan(0);
    expect(Buffer.from(pdf).subarray(0, 5).toString('utf8')).toBe('%PDF-');
  });

  it('selects the right renderer based on format', async () => {
    const html = await generateRenderedReport('html', makeJsonReporter());
    expect(typeof html.content).toBe('string');
    expect(html.extension).toBe('html');

    const pdf = await generateRenderedReport('pdf', makeJsonReporter());
    expect(pdf.content).toBeInstanceOf(Uint8Array);
    expect(pdf.extension).toBe('pdf');
  });
});
