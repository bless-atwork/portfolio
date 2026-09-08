# Blessing Kwenda — Portfolio

High-end bento-grid portfolio for Blessing Kwenda: data science student with software engineering skills.

## Stack

- Vite
- Vanilla HTML / CSS / JS
- Three.js (soft particle field)
- GSAP (entrance motion)
- Firebase Hosting + Analytics

## Local development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
npm run preview
```

## Deploy

Firebase Hosting project: `blessatworkportolio`

Live site: https://blessatworkportolio.web.app

```bash
npm run build
npx firebase deploy --only hosting
```

Pushing to `main` deploys via GitHub Actions once the Firebase service account secret is set:

```bash
# One-time: connect GitHub Actions to Firebase Hosting
npx firebase-tools init hosting:github
```

That creates `FIREBASE_SERVICE_ACCOUNT_BLESSATWORKPORTOLIO` in the repo secrets. Vite Firebase keys are already stored as `VITE_FIREBASE_*` secrets.

## Customize

- Copy `.env.example` to `.env` and fill Firebase web config
- Replace the portrait placeholder by adding `src/assets/portrait.jpg` and wiring it in `index.html`
- Edit copy and projects in `src/content.js`

## Links

- GitHub: https://github.com/bless-atwork
- Email: blessatwork@gmail.com
