# Release Checklist (Web + Mobile + API)

## 1) Prerequisiti
- `npm install -g eas-cli`
- `eas login`

## 2) Frontend env
Nella root `document_analyzer_rn/.env`:
```bash
EXPO_PUBLIC_API_BASE=https://YOUR_API_DOMAIN
```

## 3) API deploy (Render)
Da `document_analyzer_rn/server`:
- deploy con `render.yaml`
- imposta env:
  - `HF_TOKEN`
  - `JWT_SECRET` (random lungo)
  - `CORS_ORIGIN` (dominio web pubblico)
  - `NODE_ENV=production`
  - `USERS_FILE=/var/data/users.json`

## 4) Config progetto mobile
```bash
cd /Users/nicolaviola/flutter/document_analyzer_rn
eas build:configure
```

## 5) Variabili ambiente mobile (prod)
```bash
eas secret:create --name EXPO_PUBLIC_API_BASE --value https://analysispdf-api.onrender.com
```

## 6) Build web statica
```bash
npx expo export -p web
```
Output: cartella `dist/`.

## 7) Build mobile
### iOS (TestFlight)
```bash
eas build -p ios --profile production
```

### Android (Play Console)
```bash
eas build -p android --profile production
```

## 8) Pubblicazione
### Web
- deploy della cartella `dist/` (Vercel/Netlify/Cloudflare Pages)
- verifica login, upload PDF/immagine, sintesi e export PDF

### iOS
- App Store Connect → TestFlight → carica build
- invia in review quando pronto

### Android
- Play Console → Create app → carica AAB
- complete listing → invia in review

## 9) Versioning
- incrementa `expo.version` in `app.json`
- se necessario aggiorna build number in App Store Connect / Play Console
