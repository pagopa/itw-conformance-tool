export const getFormPostFromRedirectUriAndJwt = (redirectUri: string, jwt: string): string => `
  <html>
    <head>
      <title>Submit This Form</title>
    </head>
    <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="${redirectUri}">
        <input type="hidden" name="response" value="${jwt}" />
      </form>
    </body>
  </html>
`;
