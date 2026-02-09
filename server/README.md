# Document Analyzer Backend (Render)

Backend Node/Express per:
- autenticazione email/password
- estrazione testo PDF
- OCR immagini
- sintesi tramite HuggingFace

## Endpoints
- `GET /health`
- `POST /auth/register` → `{ email, password }`
- `POST /auth/login` → `{ email, password }`
- `POST /extract-pdf` (multipart file) → `{ text }`
- `POST /ocr` (multipart file) → `{ text }`
- `POST /analyze` → `{ text }` → `{ summary }`

Tutti gli endpoint tranne `/health`, `/auth/*` richiedono header:
```
Authorization: Bearer <token>
```

## Render deploy
1) Crea Web Service su Render con root `document_analyzer_rn/server`
2) Env vars:
   - `HF_TOKEN` = token HuggingFace
   - `JWT_SECRET` = stringa lunga casuale
   - `CORS_ORIGIN` = dominio web consentito (es. `https://your-web-domain.com`)
   - `USERS_FILE` = `/var/data/users.json` (se usi disk)
   - `MAX_UPLOAD_BYTES` = `5242880` (consigliato)
3) (Consigliato) aggiungi Render Disk e mount su `/var/data`

## Avvio locale
```
HF_TOKEN=IL_TUO_TOKEN JWT_SECRET=dev_secret CORS_ORIGIN=http://localhost:8081 npm run start
```
