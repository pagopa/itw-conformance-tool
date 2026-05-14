const escapeHtmlAttribute = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

const validateRedirectUri = (redirectUri: string): string => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(redirectUri);
  } catch {
    throw new Error('Invalid redirectUri');
  }

  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new Error('Invalid redirectUri protocol');
  }

  return redirectUri;
};

export const getFormPostFromRedirectUriAndJwt = (redirectUri: string, jwt: string): string => {
  const safeRedirectUri = escapeHtmlAttribute(validateRedirectUri(redirectUri));
  const safeJwt = escapeHtmlAttribute(jwt);

  return `
  <html>
    <head>
      <title>Submit This Form</title>
    </head>
    <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="${safeRedirectUri}">
        <input type="hidden" name="response" value="${safeJwt}" />
      </form>
    </body>
  </html>
`;
};
