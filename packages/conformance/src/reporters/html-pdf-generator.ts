import puppeteer from 'puppeteer';

import type { JsonReporterAssertionResult, JsonReporterResult } from './json-reporter.js';
import type { Browser } from 'puppeteer';

export type ReportFormat = 'html' | 'pdf';

export interface RenderedReport {
  content: string | Uint8Array;
  extension: ReportFormat;
  mimeType: string;
}

export interface HtmlPdfGeneratorOptions {
  generatedAt?: Date;
  title?: string;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function assertionBadgeClass(status: JsonReporterAssertionResult['status']): string {
  if (status === 'passed') {
    return 'ok';
  }
  if (status === 'failed') {
    return 'ko';
  }
  return 'pending';
}

function assertionLabel(status: JsonReporterAssertionResult['status']): string {
  if (status === 'passed') {
    return 'PASS';
  }
  if (status === 'failed') {
    return 'FAIL';
  }
  return 'NOT_REACHED';
}

export function renderHtmlReport(jsonReporter: JsonReporterResult, options: HtmlPdfGeneratorOptions = {}): string {
  const title = options.title ?? `Conformance Report - ${jsonReporter.meta.runId}`;
  const generatedAt = (options.generatedAt ?? new Date()).toISOString();

  const suites = jsonReporter.testResults
    .map((suite) => {
      const assertions = suite.assertionResults
        .map((assertion) => {
          const failures =
            assertion.failureMessages.length > 0
              ? `<div class="failure">${escapeHtml(assertion.failureMessages.join(' | '))}</div>`
              : '';

          return `<tr>
<td>${escapeHtml(suite.name)}</td>
<td>${escapeHtml(assertion.meta.requirementId)}</td>
<td>${escapeHtml(assertion.title)}</td>
<td><span class="badge ${assertionBadgeClass(assertion.status)}">${assertionLabel(assertion.status)}</span></td>
<td>${assertion.meta.httpStatus ?? '-'}</td>
<td>${escapeHtml(assertion.meta.timestamp || '-')}</td>
<td>${failures}</td>
</tr>`;
        })
        .join('\n');

      return assertions;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --card: #ffffff;
      --ink: #142033;
      --muted: #5f6e7a;
      --ok: #1f7a3f;
      --ko: #a11d2f;
      --pending: #8a5b14;
      --border: #d9e1e7;
    }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 24px; background: radial-gradient(circle at top right, #e9f2ff, var(--bg)); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    .container { max-width: 1200px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px; box-shadow: 0 8px 25px rgba(20, 32, 51, 0.06); }
    h1 { margin: 0 0 8px; font-size: 24px; }
    .meta { color: var(--muted); font-size: 13px; margin-bottom: 12px; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 10px; margin: 14px 0 16px; }
    .stat { border: 1px solid var(--border); border-radius: 10px; padding: 10px; background: #fbfcfe; }
    .stat .k { color: var(--muted); font-size: 12px; }
    .stat .v { font-size: 20px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid var(--border); padding: 10px 8px; vertical-align: top; text-align: left; }
    th { color: var(--muted); font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .badge.ok { color: var(--ok); background: #e8f7ee; }
    .badge.ko { color: var(--ko); background: #fdecef; }
    .badge.pending { color: var(--pending); background: #fff5e6; }
    .failure { color: var(--ko); }
  </style>
</head>
<body>
  <main class="container card">
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">
      Run ID: ${escapeHtml(jsonReporter.meta.runId)} | Status: ${escapeHtml(jsonReporter.meta.status)} | Started: ${escapeHtml(jsonReporter.meta.startedAt)} | Closed: ${escapeHtml(jsonReporter.meta.closedAt ?? '-')}
    </div>
    <div class="meta">Generated at: ${escapeHtml(generatedAt)}</div>

    <section class="stats">
      <article class="stat"><div class="k">Suites</div><div class="v">${jsonReporter.numTotalTestSuites}</div></article>
      <article class="stat"><div class="k">Tests</div><div class="v">${jsonReporter.numTotalTests}</div></article>
      <article class="stat"><div class="k">Passed</div><div class="v">${jsonReporter.numPassedTests}</div></article>
      <article class="stat"><div class="k">Failed</div><div class="v">${jsonReporter.numFailedTests}</div></article>
    </section>

    <table>
      <thead>
        <tr>
          <th>Step</th>
          <th>Requirement</th>
          <th>Description</th>
          <th>Result</th>
          <th>HTTP</th>
          <th>Timestamp</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        ${suites}
      </tbody>
    </table>
  </main>
</body>
</html>`;
}

export async function renderPdfReport(
  jsonReporter: JsonReporterResult,
  options: HtmlPdfGeneratorOptions = {}
): Promise<Uint8Array> {
  const html = renderHtmlReport(jsonReporter, options);
  let browser: Browser | undefined;

  try {
    browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });
    return await page.pdf({ format: 'A4', printBackground: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to render PDF report: ${message}`, { cause: error });
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

export async function generateRenderedReport(
  format: ReportFormat,
  jsonReporter: JsonReporterResult,
  options: HtmlPdfGeneratorOptions = {}
): Promise<RenderedReport> {
  if (format === 'html') {
    return {
      content: renderHtmlReport(jsonReporter, options),
      extension: 'html',
      mimeType: 'text/html; charset=utf-8'
    };
  }

  return {
    content: await renderPdfReport(jsonReporter, options),
    extension: 'pdf',
    mimeType: 'application/pdf'
  };
}
