const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

/** Escapes text for safe interpolation into HTML element content/attributes.
 *
 * @param value - The untrusted text.
 * @returns The text with HTML-significant characters replaced by entities.
 */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPE_MAP[char] as string);
}

/**
 * Serializes a string as a JS string literal safe to inline in a `<script>`
 * element: escapes quotes/backslashes via `JSON.stringify` and additionally
 * neutralizes `<`, `>`, and `&` so the literal cannot prematurely close the
 * surrounding `<script>` tag or be misinterpreted as HTML.
 *
 * @param value - The value to embed in an inline script.
 * @returns A quoted JavaScript string literal.
 */
export function toInlineScriptStringLiteral(value: string): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
}
