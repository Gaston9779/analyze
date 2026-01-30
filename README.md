# Document Analyzer (Expo + Web + Backend API)

App React Native/Expo con supporto Android, iOS e Web.

## Requisiti
- Node 20+
- npm

## Frontend locale
```bash
cd document_analyzer_rn
npm install
npx expo start
```

## Backend locale
```bash
cd document_analyzer_rn/server
npm install
HF_TOKEN=YOUR_HF_TOKEN JWT_SECRET=YOUR_SECRET CORS_ORIGIN=http://localhost:8081 npm run start
```

## Variabili frontend
Configura l'API base URL in un file `.env` nella root del progetto:
```bash
EXPO_PUBLIC_API_BASE=https://your-api-domain.com
```

## Build Web statica
```bash
cd document_analyzer_rn
npx expo export -p web
```
Output in `dist/`.

## Deploy Web (frontend)
Puoi pubblicare `dist/` su Vercel, Netlify, Cloudflare Pages o hosting statico equivalente.

## Deploy API (Render)
Usa `document_analyzer_rn/render.yaml` per deploy completo API + Web, oppure `document_analyzer_rn/server/render.yaml` per sola API.

Servizi previsti:
- API: `analysispdf-api`
- Web: `analysispdf`

Per il deploy imposta:
- `HF_TOKEN`
- `JWT_SECRET`
- `CORS_ORIGIN` (es. `https://analysispdf.onrender.com`)

Il file utenti viene salvato su disk persistente Render in `/var/data/users.json`.
