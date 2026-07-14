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

function assertionBadgeClass(status: JsonReporterAssertionResult['status']): 'ok' | 'ko' | 'pending' {
  if (status === 'passed') return 'ok';
  if (status === 'failed') return 'ko';
  return 'pending';
}

function assertionLabel(status: JsonReporterAssertionResult['status']): string {
  if (status === 'passed') return 'SUPERATO';
  if (status === 'failed') return 'FALLITO';
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
      label: 'Conformità completa',
      bannerBg: '#f0fdf4',
      bannerBorder: '#bbf7d0',
      bannerText: '#15803d'
    };
  }
  if (percent >= 50) {
    return {
      key: 'partial',
      label: 'Conformità parziale',
      bannerBg: '#fffbeb',
      bannerBorder: '#fde68a',
      bannerText: '#92400e'
    };
  }
  return {
    key: 'low',
    label: 'Conformità bassa',
    bannerBg: '#fef2f2',
    bannerBorder: '#fecdd3',
    bannerText: '#be123c'
  };
}

function statusIcon(status: JsonReporterAssertionResult['status']): string {
  if (status === 'passed') return '✓';
  if (status === 'failed') return '!';
  return '▲';
}

export function renderHtmlReport(jsonReporter: JsonReporterResult, options: HtmlPdfGeneratorOptions = {}): string {
  const title = options.title ?? 'IT-Wallet Conformance Report';
  const generatedAt = options.generatedAt ?? new Date();
  const totalTests = Math.max(jsonReporter.numTotalTests, 1);
  const compliancePercent = Math.round((jsonReporter.numPassedTests / totalTests) * 100);
  const ct = computeComplianceTheme(compliancePercent);
  const reportVersion = options.reportVersion ?? 'V. 2.3.1';
  const solutionEntity = options.solutionEntity ?? '-';
  const solutionName = options.solutionName ?? '-';
  const profile = options.profile ?? '-';
  const rulesVersion = options.rulesVersion ?? '-';
  const isComplete = compliancePercent >= 100;

  const criticalFailures = jsonReporter.testResults
    .flatMap((suite) => suite.assertionResults.filter((a) => a.status === 'failed').map((a) => a.title))
    .slice(0, 5);

  const showCritical = !isComplete && criticalFailures.length > 0;

  const passedWord = jsonReporter.numPassedTests === 1 ? 'è stato superato' : 'sono stati superati';
  const partialWord = jsonReporter.numPendingTests === 1 ? 'è parzialmente conforme' : 'sono parzialmente conformi';
  const failedWord = jsonReporter.numFailedTests === 1 ? 'è fallito' : 'sono falliti';
  const controlWord = isComplete ? 'di validazione' : 'di conformità';

  const sintesiP1 = `${escapeHtml(solutionEntity)} ha eseguito ${isComplete ? 'la validazione di conformità' : 'una verifica di conformità'} per ${escapeHtml(solutionName)} (profilo ${escapeHtml(profile)}) secondo le Regole Tecniche ${escapeHtml(rulesVersion)} il ${escapeHtml(jsonReporter.meta.startedAt)}.`;
  const sintesiP2 = `Su ${jsonReporter.numTotalTests} controlli ${controlWord}, ${jsonReporter.numPassedTests} ${passedWord} con successo, ${jsonReporter.numPendingTests} ${partialWord} e ${jsonReporter.numFailedTests} ${failedWord}. Questo porta a un tasso di conformità del ${compliancePercent}% e a uno stato complessivo di <strong style="color:${ct.bannerText}">${escapeHtml(ct.label)}</strong>.`;

  const detailRows: Array<{ icon: string; label: string; value: string; full?: boolean }> = [
    { icon: '🏛', label: 'Ente', value: solutionEntity },
    { icon: '', label: 'Nome della soluzione', value: solutionName },
    { icon: '', label: 'Profilo', value: profile },
    { icon: '🗓', label: "Data e ora dell'esecuzione", value: jsonReporter.meta.startedAt },
    { icon: '', label: 'Versione delle regole tecniche', value: rulesVersion, full: true }
  ];

  const detailHtml = detailRows
    .map(
      (row) =>
        `<article class="det-card${row.full ? ' det-full' : ''}">
          <div class="det-lbl">${row.icon ? `<span>${escapeHtml(row.icon)}</span> ` : ''}${escapeHtml(row.label)}</div>
          <div class="det-val">${escapeHtml(row.value)}</div>
        </article>`
    )
    .join('');

  const criticalHtml = showCritical
    ? `<div class="crit-box">
        <p class="crit-title">Problemi critici che richiedono un'azione correttiva:</p>
        <div class="crit-list">
          ${criticalFailures.map((item) => `<div class="crit-item">${escapeHtml(item)}</div>`).join('')}
        </div>
      </div>`
    : '';

  const controlsHtml = jsonReporter.testResults
    .flatMap((suite) =>
      suite.assertionResults.map((a) => {
        const cls = assertionBadgeClass(a.status);
        const ctrlId = a.meta.requirementId ?? a.title;
        const hasDetail = a.failureMessages.length > 0;
        const detailBoxes = hasDetail
          ? `<div class="ctrl-details">
              <div class="ctrl-det-row ${cls === 'ko' ? 'det-fail' : 'det-warn'}">
                <div class="ctrl-det-k">Problema Identificato:</div>
                <div class="ctrl-det-v">${escapeHtml(a.failureMessages[0] ?? '-')}</div>
              </div>
              <div class="ctrl-det-row ${cls === 'ko' ? 'det-fail' : 'det-warn'}">
                <div class="ctrl-det-k">Motivo:</div>
                <div class="ctrl-det-v">${escapeHtml(a.failureMessages.slice(1).join(' | ') || a.title)}</div>
              </div>
            </div>`
          : '';

        return `<article class="ctrl-card ctrl-${cls}">
          <div class="ctrl-row">
            <div class="ctrl-l">
              <span class="ctrl-icon ctrl-icon-${cls}">${statusIcon(a.status)}</span>
              <div class="ctrl-info">
                <div class="ctrl-hd">
                  <span class="ctrl-id">${escapeHtml(ctrlId)}</span>
                  <span class="ctrl-name">${escapeHtml(a.title)}</span>
                </div>
                ${a.meta.requirementId ? `<div class="ctrl-req">${escapeHtml(a.meta.requirementId)}</div>` : ''}
              </div>
            </div>
            <span class="ctrl-badge ctrl-badge-${cls}">${assertionLabel(a.status)}</span>
          </div>
          ${detailBoxes}
        </article>`;
      })
    )
    .join('');

  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Wallet Conformance Tool Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#f0f1f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#111827}
    .page{padding:32px 24px;min-height:100vh}
    .page-lbl{color:#9ca3af;font-size:13px;margin-bottom:12px}
    .card{max-width:960px;margin:0 auto;background:#fff;border-radius:20px;padding:36px;box-shadow:0 4px 24px rgba(0,0,0,.07)}
    .rpt-hdr{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:24px}
    .rpt-title{font-size:26px;font-weight:700;color:#111827;line-height:1.2}
    .rpt-sub{font-size:13px;color:#6b7280;margin-top:5px}
    .ver-badge{border:1.5px solid #d1d5db;border-radius:8px;padding:6px 14px;font-size:13px;font-weight:600;color:#374151;white-space:nowrap}
    .banner{border-radius:12px;padding:20px 24px;display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}
    .banner-l{display:flex;flex-direction:column;gap:6px}
    .banner-meta{font-size:12px;font-weight:500}
    .banner-status{font-size:28px;font-weight:700;line-height:1.2}
    .banner-r{text-align:right;flex-shrink:0}
    .banner-pct{font-size:52px;font-weight:700;line-height:1}
    .banner-pct-lbl{font-size:12px;font-weight:500;margin-top:3px}
    .section{margin-top:28px}
    .sec-title{font-size:16px;font-weight:600;color:#111827;margin-bottom:14px;display:flex;align-items:center;gap:7px}
    .det-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .det-card{border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;background:#fafafa}
    .det-full{grid-column:1/-1}
    .det-lbl{font-size:12px;color:#6b7280;margin-bottom:5px}
    .det-val{font-size:14px;font-weight:600;color:#111827}
    .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
    .stat{border-radius:10px;padding:16px;border:1.5px solid}
    .stat-lbl{font-size:12px;font-weight:500;margin-bottom:8px}
    .stat-val{font-size:34px;font-weight:700;line-height:1}
    .s-total{border-color:#d1d5db;background:#f9fafb}.s-total .stat-lbl,.s-total .stat-val{color:#4b5563}
    .s-pass{border-color:#86efac;background:#f0fdf4}.s-pass .stat-lbl,.s-pass .stat-val{color:#15803d}
    .s-partial{border-color:#fde68a;background:#fffbeb}.s-partial .stat-lbl,.s-partial .stat-val{color:#92400e}
    .s-fail{border-color:#fca5a5;background:#fef2f2}.s-fail .stat-lbl,.s-fail .stat-val{color:#be123c}
    .sintesi{font-size:14px;color:#374151;line-height:1.75}
    .sintesi p{margin-bottom:10px}
    .crit-box{margin-top:16px;border:1.5px solid #fca5a5;border-radius:10px;background:#fff5f5;padding:16px}
    .crit-title{font-size:13px;font-weight:600;color:#be123c;margin-bottom:10px}
    .crit-list{display:flex;flex-direction:column;gap:6px}
    .crit-item{background:#fff;border:1px solid #fee2e2;border-radius:7px;padding:10px 14px;color:#be123c;font-size:13px;font-weight:500}
    .ctrl-list{display:flex;flex-direction:column;gap:10px}
    .ctrl-card{border-radius:12px;border:1.5px solid;padding:16px}
    .ctrl-ok{border-color:#86efac;background:#f0fdf4}
    .ctrl-ko{border-color:#fca5a5;background:#fef2f2}
    .ctrl-pending{border-color:#fde68a;background:#fffbeb}
    .ctrl-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
    .ctrl-l{display:flex;align-items:flex-start;gap:12px;flex:1;min-width:0}
    .ctrl-icon{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;flex-shrink:0;margin-top:1px}
    .ctrl-icon-ok{background:#15803d;color:#fff}
    .ctrl-icon-ko{background:#be123c;color:#fff}
    .ctrl-icon-pending{background:#92400e;color:#fff}
    .ctrl-info{flex:1;min-width:0}
    .ctrl-hd{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    .ctrl-id{font-size:11px;font-weight:700;color:#6b7280;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:5px;padding:2px 8px;white-space:nowrap}
    .ctrl-name{font-size:14px;font-weight:600;color:#111827}
    .ctrl-req{font-size:11px;color:#9ca3af;margin-top:3px}
    .ctrl-badge{border-radius:999px;padding:5px 13px;font-size:11px;font-weight:700;white-space:nowrap;flex-shrink:0}
    .ctrl-badge-ok{color:#15803d;background:#dcfce7}
    .ctrl-badge-ko{color:#be123c;background:#fee2e2}
    .ctrl-badge-pending{color:#92400e;background:#fef3c7}
    .ctrl-details{margin-top:12px;display:flex;flex-direction:column;gap:8px}
    .ctrl-det-row{border:1px solid #e5e7eb;border-left:4px solid;border-radius:8px;background:#fff;padding:10px 14px}
    .det-fail{border-left-color:#f87171}
    .det-warn{border-left-color:#fbbf24}
    .ctrl-det-k{font-size:11px;font-weight:700;color:#374151;margin-bottom:4px}
    .ctrl-det-v{font-size:13px;color:#111827}
    .rpt-footer{margin-top:32px;padding-top:20px;border-top:1px solid #e5e7eb}
    .ft-text{font-size:13px;color:#6b7280}
    .ft-id{font-size:13px;color:#374151;font-weight:500;margin-top:4px}
    .ft-date{font-size:12px;color:#9ca3af;margin-top:3px}
    @media(max-width:700px){
      .stats{grid-template-columns:1fr 1fr}
      .det-grid{grid-template-columns:1fr}
      .det-full{grid-column:auto}
      .rpt-hdr{flex-direction:column}
      .banner{flex-direction:column;gap:12px;align-items:flex-start}
      .ctrl-row{flex-direction:column}
    }
    @media print{
      body{background:#fff;padding:0}
      .card{box-shadow:none;border:none;border-radius:0}
      .ctrl-card{page-break-inside:avoid}
    }
  </style>
</head>
<body>
  <div class="page">
    <p class="page-lbl">Wallet Conformance Tool Report</p>
    <main class="card">

      <header class="rpt-hdr">
        <div>
          <h1 class="rpt-title">${escapeHtml(title)}</h1>
          <p class="rpt-sub">Risultato della verifica di conformità tecnica</p>
        </div>
        <span class="ver-badge">${escapeHtml(reportVersion)}</span>
      </header>

      <div class="banner" style="background:${ct.bannerBg};border:1.5px solid ${ct.bannerBorder};color:${ct.bannerText}">
        <div class="banner-l">
          <span class="banner-meta">Stato di Conformità Complessivo</span>
          <span class="banner-status">${escapeHtml(ct.label)}</span>
        </div>
        <div class="banner-r">
          <div class="banner-pct">${compliancePercent}%</div>
          <div class="banner-pct-lbl">Tasso di Conformità</div>
        </div>
      </div>

      <section class="section">
        <h2 class="sec-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>
          Dettagli del test
        </h2>
        <div class="det-grid">${detailHtml}</div>
      </section>

      <section class="section">
        <h2 class="sec-title">${isComplete ? 'Riepilogo Validazione' : 'Riepilogo della verifica'}</h2>
        <div class="stats">
          <article class="stat s-total"><div class="stat-lbl">Controlli Totali</div><div class="stat-val">${jsonReporter.numTotalTests}</div></article>
          <article class="stat s-pass"><div class="stat-lbl">Superati</div><div class="stat-val">${jsonReporter.numPassedTests}</div></article>
          <article class="stat s-partial"><div class="stat-lbl">Parziali</div><div class="stat-val">${jsonReporter.numPendingTests}</div></article>
          <article class="stat s-fail"><div class="stat-lbl">Falliti</div><div class="stat-val">${jsonReporter.numFailedTests}</div></article>
        </div>
      </section>

      <section class="section">
        <h2 class="sec-title">Sintesi Esecutiva</h2>
        <div class="sintesi">
          <p>${sintesiP1}</p>
          <p>${sintesiP2}</p>
        </div>
        ${criticalHtml}
      </section>

      ${
        controlsHtml.trim().length > 0
          ? `<section class="section">
        <h2 class="sec-title">Dettaglio dei controlli di conformità</h2>
        <div class="ctrl-list">${controlsHtml}</div>
      </section>`
          : ''
      }

      <footer class="rpt-footer">
        <p class="ft-text">Questo rapporto è stato generato automaticamente dallo Strumento di Conformità IT-Wallet.</p>
        <p class="ft-id">ID Rapporto: ${escapeHtml(jsonReporter.meta.runId)}</p>
        <p class="ft-date">Generato il: ${escapeHtml(generatedAt.toLocaleString('it-IT'))}</p>
      </footer>

    </main>
  </div>
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
