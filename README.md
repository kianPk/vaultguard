# Vaultguard

**Defensive secrets toolkit** — password scoring, secret-shape scanner, JWT decode (no verify), Web Crypto hashing.

Live demo: **https://kianpk.github.io/vaultguard/**

## Stack

Vue 3 · Vite · Express · Zod · Web Crypto

## Notes

- JWT tool **decodes only** — it does not verify signatures.
- Secret scan looks for common *shapes* (AWS key id pattern, JWT, PEM headers, etc.) for redaction hygiene.
- Password scoring flags **repeat sequences** (e.g. `abcabc`, `aaa`) and **keyboard walks** (`qwerty`, row fragments like `asdf`) in the breakdown checks.
- Never paste real production secrets into public demos.

## Run

```bash
cd server && npm i && node index.js
cd client && npm i && npm run dev
cd client && npm run build   # → docs/
```
