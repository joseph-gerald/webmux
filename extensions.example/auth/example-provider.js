// External auth-provider scaffold. Copy to extensions/auth/ and adapt it to
// your identity service. See README.md in this directory for the core contract.
// This file cannot authenticate anyone as shipped.

module.exports = {
  id: 'example',
  label: 'Sign in with Example',
  kind: 'oauth',

  register(ctx) {
    // Remove this only after implementing and testing your provider's protocol.
    throw new Error('Example provider is a scaffold; implement verified login before enabling it');

    // Mount /start and /callback on ctx.router. Build redirect URLs from
    // ctx.publicUrl, and validate it and your identity service URL as HTTPS.
    // Use the identity service's supported verifier/client. Bind each callback
    // to the initiating browser with single-use state (and PKCE for OAuth).
    // Verify signatures, issuer, audience, expiry and replay protection as
    // required by that protocol. Never trust a username supplied by a request.
    // Do not put bearer credentials in redirect URLs or logs.
    //
    // Only after successful verification, finish the login like this:
    // const token = ctx.mintToken({ user: verifiedUsername,
    //   ip: ctx.clientIp(req), ua: req.headers['user-agent'] });
    // if (!token) return res.status(403).send('access denied');
    // ctx.setSessionCookie(res, token);
    // res.redirect(303, ctx.publicUrl + '/');
  },
};
