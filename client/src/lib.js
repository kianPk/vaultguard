const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']

const KEYBOARD_WALKS = [
  'qwerty',
  'asdfgh',
  'zxcvbn',
  '123456',
  '654321',
  'qazwsx',
  '1qaz2wsx',
  'password',
]

function hasKeyboardWalk(pw) {
  const lower = pw.toLowerCase()
  for (const walk of KEYBOARD_WALKS) {
    if (lower.includes(walk)) return true
  }
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - 4; i++) {
      const seq = row.slice(i, i + 4)
      if (lower.includes(seq) || lower.includes(seq.split('').reverse().join(''))) return true
    }
  }
  return false
}

function hasRepeatSequence(pw) {
  if (/(.)\1{2,}/.test(pw)) return true
  for (let len = 2; len <= 4; len++) {
    const re = new RegExp(`(.{${len}})\\1+`)
    if (re.test(pw)) return true
  }
  return false
}

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

export function scorePassword(pw) {
  const checks = {
    length8: pw.length >= 8,
    length12: pw.length >= 12,
    lower: /[a-z]/.test(pw),
    upper: /[A-Z]/.test(pw),
    digit: /\d/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw),
    notCommon: !COMMON.has(pw.toLowerCase()),
    noRepeatSeq: !hasRepeatSequence(pw),
    noKeyboardWalk: !hasKeyboardWalk(pw),
  }
  let score = 0
  if (checks.length8) score += 15
  if (checks.length12) score += 20
  if (checks.lower) score += 10
  if (checks.upper) score += 15
  if (checks.digit) score += 15
  if (checks.symbol) score += 15
  if (checks.notCommon) score += 10
  if (!checks.noRepeatSeq) score -= 15
  if (!checks.noKeyboardWalk) score -= 18
  if (/^[0-9]+$/.test(pw)) score -= 20
  score = Math.max(0, Math.min(100, score))
  const label = score >= 80 ? 'strong' : score >= 55 ? 'fair' : score >= 30 ? 'weak' : 'critical'
  return { score, label, checks }
}

export const SECRET_PATTERNS = [
  { id: 'aws_key', re: /AKIA[0-9A-Z]{16}/g, label: 'AWS access key id' },
  { id: 'generic_sk', re: /sk[_-]live[_-][A-Za-z0-9]{16,}/gi, label: 'Stripe-like secret' },
  { id: 'jwt', re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, label: 'JWT token' },
  { id: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'Private key block' },
  { id: 'gh_pat', re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, label: 'GitHub token shape' },
  { id: 'slack', re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: 'Slack token shape' },
]

export function scanSecrets(text) {
  const findings = []
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags)
    const matches = text.match(re) || []
    for (const m of matches) {
      findings.push({
        id: p.id,
        label: p.label,
        preview: m.slice(0, 6) + '…' + m.slice(-4),
        length: m.length,
      })
    }
  }
  return { findings, count: findings.length }
}

export function decodeJwt(token) {
  const parts = token.trim().split('.')
  if (parts.length < 2) throw new Error('Not a JWT')
  const b64 = (s) => {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
    const norm = s.replace(/-/g, '+').replace(/_/g, '/') + pad
    return JSON.parse(atob(norm))
  }
  return {
    header: b64(parts[0]),
    payload: b64(parts[1]),
    note: 'Decode only — signature is NOT verified by this lab tool.',
  }
}

export async function hashText(text, algo = 'SHA-256') {
  const data = new TextEncoder().encode(text)
  const buf = await crypto.subtle.digest(algo, data)
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
