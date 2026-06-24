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
  solutionEntity?: string;
  solutionName?: string;
  profile?: string;
  rulesVersion?: string;
  reportVersion?: string;
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
    return 'SUPERATO';
  }
  if (status === 'failed') {
    return 'FALLITO';
  }
  return 'PARZIALE';
}

interface ComplianceTheme {
  key: 'complete' | 'partial' | 'low';
  label: string;
  bannerBg: string;
  bannerBorder: string;
  bannerText: string;
}

function computeComplianceTheme(percent: number): ComplianceTheme {
  if (percent >= 100) {
    return {
      key: 'complete',
      label: 'Conformita completa',
      bannerBg: '#ecfdf3',
      bannerBorder: '#0e6b3f',
      bannerText: '#0e6b3f'
    };
  }

  if (percent >= 50) {
    return {
      key: 'partial',
      label: 'Conformita parziale',
      bannerBg: '#fff8e8',
      bannerBorder: '#8b5d00',
      bannerText: '#8b5d00'
    };
  }

  return {
    key: 'low',
    label: 'Conformita bassa',
    bannerBg: '#fef1f3',
    bannerBorder: '#9f1239',
    bannerText: '#9f1239'
  };
}

function statusIcon(status: JsonReporterAssertionResult['status']): string {
  if (status === 'passed') {
    return '✓';
  }

  if (status === 'failed') {
    return '!';
  }

  return '△';
}

export function renderHtmlReport(jsonReporter: JsonReporterResult, options: HtmlPdfGeneratorOptions = {}): string {
  const title = options.title ?? 'IT-Wallet Conformance Report';
  const generatedAt = (options.generatedAt ?? new Date()).toISOString();
  const totalTests = Math.max(jsonReporter.numTotalTests, 1);
  const compliancePercent = Math.round((jsonReporter.numPassedTests / totalTests) * 100);
  const complianceTheme = computeComplianceTheme(compliancePercent);
  const reportVersion = options.reportVersion ?? 'V. 2.3.1';

  const detailCards: Array<{ label: string; value: string }> = [
    { label: 'Ente', value: options.solutionEntity ?? '-' },
    { label: 'Nome della soluzione', value: options.solutionName ?? '-' },
    { label: 'Profilo', value: options.profile ?? '-' },
    { label: 'Data e ora', value: jsonReporter.meta.startedAt },
    { label: 'Versione regole', value: options.rulesVersion ?? '-' },
    { label: 'Run ID', value: jsonReporter.meta.runId }
  ];

  const criticalFailures = jsonReporter.testResults
    .flatMap((suite) =>
      suite.assertionResults
        .filter((assertion) => assertion.status === 'failed')
        .map((assertion) => `${suite.name} - ${assertion.title}`)
    )
    .slice(0, 5);

  const detailCardsHtml = detailCards
    .map(
      (item) => `<article class="detail-card">
        <div class="detail-k">${escapeHtml(item.label)}</div>
        <div class="detail-v">${escapeHtml(item.value)}</div>
      </article>`
    )
    .join('\n');

  let controlIndex = 0;

  const controls = jsonReporter.testResults
    .map((suite) => {
      return suite.assertionResults
        .map((assertion) => {
          controlIndex += 1;
          const statusClass = assertionBadgeClass(assertion.status);
          const hasDetails = assertion.failureMessages.length > 0;
          const controlId = `CI_${String(controlIndex).padStart(3, '0')}`;

          const detailsHtml = hasDetails
            ? `<section class="control-extra ${statusClass === 'ko' ? 'fail' : 'pending'}">
                <div class="extra-row">
                  <div class="extra-k">Problema Identificato</div>
                  <div class="extra-v">${escapeHtml(assertion.failureMessages[0] ?? '-')}</div>
                </div>
                <div class="extra-row">
                  <div class="extra-k">Motivo</div>
                  <div class="extra-v">${escapeHtml(assertion.failureMessages.slice(1).join(' | ') || assertion.title)}</div>
                </div>
              </section>`
            : '';

          return `<article class="control-card ${statusClass}">
            <div class="control-head">
              <div class="control-left">
                <span class="status-icon ${statusClass}">${statusIcon(assertion.status)}</span>
                <span class="control-id">${escapeHtml(controlId)}</span>
                <h3>${escapeHtml(suite.name)} - ${escapeHtml(assertion.title)}</h3>
              </div>
              <span class="badge ${statusClass}">${assertionLabel(assertion.status)}</span>
            </div>
            <div class="control-meta">
              <span>Requirement: ${escapeHtml(assertion.meta.requirementId || '-')}</span>
              <span>Step: ${escapeHtml(suite.name)}</span>
              <span>Timestamp: ${escapeHtml(assertion.meta.timestamp || '-')}</span>
              <span>HTTP: ${assertion.meta.httpStatus ?? '-'}</span>
            </div>
            ${detailsHtml}
          </article>`;
        })
        .join('\n');
    })
    .join('\n');

  const criticalIssuesHtml =
    complianceTheme.key === 'low' && criticalFailures.length > 0
      ? `<section class="critical-box">
          <h2>Problemi critici</h2>
          <ul>
            ${criticalFailures.map((item) => `<li>${escapeHtml(item)}</li>`).join('\n')}
          </ul>
        </section>`
      : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #f3f4f6;
      --card: #ffffff;
      --ink: #142033;
      --muted: #6b7280;
      --ok: #0e6b3f;
      --ko: #9f1239;
      --pending: #8b5d00;
      --border: #e5e7eb;
      --soft: #f9fafb;
      --ok-soft: #e8f4e9;
      --ko-soft: #f9e2e4;
      --pending-soft: #f8f3da;
    }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 28px; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    .container { max-width: 1024px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 20px; padding: 24px; box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08); }
    h1 { margin: 0; font-size: 32px; line-height: 1.12; font-weight: 700; color: #111827; }
    h2 { margin: 0 0 12px; font-size: 18px; color: #111827; }
    h3 { margin: 0; font-size: 14px; color: #111827; font-weight: 600; }
    .header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 16px; }
    .subtitle { color: var(--muted); font-size: 13px; margin-top: 6px; }
    .version { display: inline-flex; align-items: center; border: 1px solid var(--border); border-radius: 999px; padding: 6px 12px; color: #4b5563; font-size: 12px; font-weight: 600; }
    .banner { border: 1px solid ${complianceTheme.bannerBorder}; background: ${complianceTheme.bannerBg}; border-radius: 12px; padding: 14px; color: ${complianceTheme.bannerText}; font-weight: 700; margin: 8px 0 24px; }
    .banner small { font-weight: 600; margin-left: 8px; }
    .section { margin-top: 24px; }
    .detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .detail-card { border: 1px solid var(--border); border-radius: 12px; background: var(--soft); padding: 14px; min-height: 74px; }
    .detail-k { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .detail-v { color: #1f2937; font-size: 14px; font-weight: 600; word-break: break-word; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 10px; }
    .stat { border: 1px solid var(--border); border-radius: 12px; padding: 14px; background: #ffffff; min-height: 94px; }
    .stat .k { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .stat .v { font-size: 24px; font-weight: 700; color: #111827; }
    .stat.pass { border-color: #0e6b3f; background: #ecfdf3; }
    .stat.partial { border-color: #8b5d00; background: #fff8e8; }
    .stat.fail { border-color: #9f1239; background: #fef1f3; }
    .controls { display: grid; gap: 12px; }
    .control-card { border: 1px solid var(--border); border-radius: 12px; background: #fff; padding: 14px; }
    .control-card.ok { background: var(--ok-soft); border-color: #9bc6a8; }
    .control-card.ko { background: var(--ko-soft); border-color: #de9aa4; }
    .control-card.pending { background: var(--pending-soft); border-color: #d1bc78; }
    .control-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .control-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .control-id { display: inline-flex; align-items: center; border: 1px solid #d1d5db; border-radius: 999px; background: #f5f6f8; color: #4b5563; padding: 4px 10px; font-size: 12px; font-weight: 700; }
    .status-icon { width: 26px; height: 26px; border-radius: 999px; display: inline-flex; align-items: center; justify-content: center; font-size: 15px; font-weight: 800; }
    .status-icon.ok { color: var(--ok); background: #dcfce7; }
    .status-icon.ko { color: var(--ko); background: #ffe4e6; }
    .status-icon.pending { color: var(--pending); background: #fef3c7; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .badge.ok { color: var(--ok); background: #e8f7ee; }
    .badge.ko { color: var(--ko); background: #fdecef; }
    .badge.pending { color: var(--pending); background: #fff5e6; }
    .control-meta { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 12px; color: #6b7280; font-size: 12px; }
    .control-extra { margin-top: 10px; display: grid; gap: 8px; }
    .control-extra.fail .extra-row { border-left-color: #ef4444; }
    .control-extra.pending .extra-row { border-left-color: #eab308; }
    .extra-row { margin-bottom: 8px; }
    .extra-row:last-child { margin-bottom: 0; }
    .extra-row { border: 1px solid #e5e7eb; border-left: 4px solid #d1d5db; border-radius: 10px; background: #ffffff; padding: 10px; }
    .extra-k { color: #374151; font-size: 12px; font-weight: 700; }
    .extra-v { color: #111827; font-size: 13px; margin-top: 4px; }
    .critical-box { margin-top: 16px; border: 1px solid #fda4af; background: #ffe4e6; border-radius: 12px; padding: 12px; }
    .critical-box h2 { color: #9f1239; font-size: 16px; margin: 0 0 8px; }
    .critical-box ul { margin: 0; padding-left: 20px; }
    .critical-box li { color: #9f1239; margin: 4px 0; font-size: 13px; }
    @media (max-width: 800px) {
      .header { flex-direction: column; }
      .detail-grid { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .control-head { flex-direction: column; align-items: flex-start; }
    }
    @media print {
      body { padding: 0; background: #fff; }
      .card { box-shadow: none; border: none; border-radius: 0; }
      .control-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <main class="container card">
    <header class="header">
      <div>
        <h1>${escapeHtml(title)}</h1>
        <div class="subtitle">Report di verifica di conformita IT-Wallet</div>
      </div>
      <div class="version">${escapeHtml(reportVersion)}</div>
    </header>

    <section class="banner">
      ${escapeHtml(complianceTheme.label)}
      <small>(${compliancePercent}% di controlli superati)</small>
    </section>

    <section class="section">
      <h2>Dettagli del test</h2>
      <div class="detail-grid">
        ${detailCardsHtml}
      </div>
    </section>

    <section class="section">
      <h2>Riepilogo della verifica</h2>
      <div class="stats">
        <article class="stat"><div class="k">Controlli Totali</div><div class="v">${jsonReporter.numTotalTests}</div></article>
        <article class="stat pass"><div class="k">Superati</div><div class="v">${jsonReporter.numPassedTests}</div></article>
        <article class="stat partial"><div class="k">Parziali</div><div class="v">${jsonReporter.numPendingTests}</div></article>
        <article class="stat fail"><div class="k">Falliti</div><div class="v">${jsonReporter.numFailedTests}</div></article>
      </div>
    </section>

    ${criticalIssuesHtml}

    <section class="section">
      <h2>Dettaglio dei controlli di conformita</h2>
      <div class="controls">
        ${controls}
      </div>
    </section>

    <div class="subtitle" style="margin-top: 18px;">
      Stato run: ${escapeHtml(jsonReporter.meta.status)} | Avvio: ${escapeHtml(jsonReporter.meta.startedAt)} | Chiusura: ${escapeHtml(jsonReporter.meta.closedAt ?? '-')} | Generato: ${escapeHtml(generatedAt)}
    </div>
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
    return await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '12mm', right: '12mm', bottom: '12mm', left: '12mm' }
    });
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
