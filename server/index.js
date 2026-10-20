import express from 'express'
import cors from 'cors'
import { z } from 'zod'
import crypto from 'crypto'

const PORT = process.env.PORT || 8812
const app = express()
app.use(cors())
app.use(express.json({ limit: '256kb' }))

const COMMON = new Set([
  'password',
  '123456',
  'qwerty',
  'admin',
  'letmein',
  'welcome',
  'iloveyou',
  'monkey',
  'dragon',
  'password1',
])

function scorePassword(pw) {
  const checks = {
    length8: pw.length >= 8,
    length12: pw.length >= 12,
    lower: /[a-z]/.test(pw),
    upper: /[A-Z]/.test(pw),
    digit: /\d/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw),
    notCommon: !COMMON.has(pw.toLowerCase()),
  }
  let score = 0
  if (checks.length8) score += 15
  if (checks.length12) score += 20
  if (checks.lower) score += 10
  if (checks.upper) score += 15
  if (checks.digit) score += 15
  if (checks.symbol) score += 15
  if (checks.notCommon) score += 10
  if (/(.)\1{2,}/.test(pw)) score -= 10
  if (/^[0-9]+$/.test(pw)) score -= 20
  score = Math.max(0, Math.min(100, score))
  const label = score >= 80 ? 'strong' : score >= 55 ? 'fair' : score >= 30 ? 'weak' : 'critical'
  return { score, label, checks }
}

const SECRET_PATTERNS = [
  { id: 'aws_key', re: /AKIA[0-9A-Z]{16}/g, label: 'AWS access key id' },
  { id: 'generic_sk', re: /sk[_-]live[_-][A-Za-z0-9]{16,}/gi, label: 'Stripe-like secret' },
  { id: 'jwt', re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, label: 'JWT token' },
  { id: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'Private key block' },
  { id: 'gh_pat', re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, label: 'GitHub token shape' },
  { id: 'slack', re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: 'Slack token shape' },
]

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'vaultguard' }))

app.post('/api/password/score', (req, res) => {
  const schema = z.object({ password: z.string().max(256) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'Invalid' })
  res.json(scorePassword(parsed.data.password))
})

app.post('/api/secrets/scan', (req, res) => {
  const schema = z.object({ text: z.string().max(100_000) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'Invalid' })
  const text = parsed.data.text
  const findings = []
  for (const p of SECRET_PATTERNS) {
    const matches = text.match(p.re) || []
    for (const m of matches) {
      findings.push({
        id: p.id,
        label: p.label,
        preview: m.slice(0, 6) + '…' + m.slice(-4),
        length: m.length,
      })
    }
  }
  res.json({ findings, count: findings.length })
})

app.post('/api/jwt/decode', (req, res) => {
  const schema = z.object({ token: z.string().max(8000) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'Invalid' })
  const parts = parsed.data.token.split('.')
  if (parts.length < 2) return res.status(400).json({ error: 'Not a JWT' })
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    res.json({
      header,
      payload,
      note: 'Decode only — signature is NOT verified by this lab tool.',
    })
  } catch {
    res.status(400).json({ error: 'Malformed JWT segments' })
  }
})

app.post('/api/hash', (req, res) => {
  const schema = z.object({
    text: z.string().max(50_000),
    algo: z.enum(['sha256', 'sha512', 'sha1', 'md5']).default('sha256'),
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'Invalid' })
  const { text, algo } = parsed.data
  const digest = crypto.createHash(algo).update(text, 'utf8').digest('hex')
  res.json({ algo, digest })
})

app.listen(PORT, () => console.log(`vaultguard on :${PORT}`))
