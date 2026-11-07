# Firebase web API key is shipped to the browser

- Rule: `firebase-web-api-key`
- Observed this run: 1
- Environmental severity: low
- Category: auth

Restrict the key by HTTP referrer and API in Google Cloud. Keep Firestore and Storage rules closed by default.

Locations:
- `src/main.js`

Likelihood and impact are estimates for prioritisation, not a statement that an exploit was attempted.
