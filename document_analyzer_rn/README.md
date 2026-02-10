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
HF_TOKEN=YOUR_HF_TOKEN JWT_SECRET=YOUR_SECRET CORS_ORIGIN=http://localhost:8081 CORS_ALLOW_ONRENDER_WILDCARD=false npm run start
```

## Variabili frontend
Configura l'API base URL in un file `.env` nella root del progetto:
```bash
EXPO_PUBLIC_API_BASE=https://your-api-domain.com
```
Puoi partire da `.env.example`.

## Build Web statica
```bash
cd document_analyzer_rn
npx expo export -p web
```
Output in `dist/`.

## Deploy Web (frontend)
Puoi pubblicare `dist/` su Vercel, Netlify, Cloudflare Pages o hosting statico equivalente.

## Deploy API (Render)
Usa `render.yaml` (root) per deploy completo API + Web, oppure `server/render.yaml` per sola API.

Servizi previsti:
- API: `analysispdf-api`
- Web: `analysispdf`

Per il deploy imposta:
- `NODE_ENV=production`
- `HF_TOKEN`
- `JWT_SECRET`
- `CORS_ORIGIN` (es. `https://analysispdf.onrender.com`)
- `CORS_ALLOW_ONRENDER_WILDCARD=true` (consigliato su Render)
- `USERS_FILE=/tmp/users.json` (Render free tier, non persistente)
- `MAX_UPLOAD_BYTES=5242880`

Per l'API puoi partire da `server/.env.example`.
