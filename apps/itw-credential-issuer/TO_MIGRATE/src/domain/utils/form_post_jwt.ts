export const getFormPostFromRedirectUriAndJwt = (redirect_uri: string, jwt: string) => `
  <html>
    <head>
      <title>Submit This Form</title>
    </head>
    <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="${redirect_uri}">
        <input type="hidden" name="response" value="${jwt}" />
      </form>
    </body>
  </html>
`;
