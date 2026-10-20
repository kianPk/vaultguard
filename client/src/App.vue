<script setup>
import { computed, ref, watch } from 'vue'
import { scorePassword, scanSecrets, decodeJwt, hashText } from './lib'

const tab = ref('password')
const password = ref('')
const paste = ref(
  `config:\n  aws_key: AKIAIOSFODNN7EXAMPLE\n  note: sample shapes for demo only\n  token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJraWFuIiwicm9sZSI6ImRldiJ9.signature`,
)
const jwt = ref(
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJraWFuUGsiLCJuYW1lIjoiS2lhbiBaYXJhbmRpIiwiaWF0IjoxNzAwMDAwMDAwfQ.demo',
)
const hashInput = ref('vaultguard')
const hashAlgo = ref('SHA-256')
const hashOut = ref('')
const jwtOut = ref(null)
const jwtErr = ref('')
const scan = ref(null)

const pw = computed(() => scorePassword(password.value || ''))

watch(
  paste,
  (t) => {
    scan.value = scanSecrets(t)
  },
  { immediate: true },
)

function runJwt() {
  jwtErr.value = ''
  try {
    jwtOut.value = decodeJwt(jwt.value)
  } catch (e) {
    jwtOut.value = null
    jwtErr.value = e.message
  }
}

async function runHash() {
  hashOut.value = await hashText(hashInput.value, hashAlgo.value)
}
</script>

<template>
  <div class="shell">
    <header>
      <div>
        <p class="eyebrow">Defensive security toolkit</p>
        <h1>Vaultguard</h1>
        <p class="lede">Password scoring · secret redaction scan · JWT decode · hashing — all client-side on Pages.</p>
      </div>
      <div class="seal" aria-hidden="true" />
    </header>

    <nav class="tabs">
      <button type="button" :class="{ on: tab === 'password' }" @click="tab = 'password'">Password</button>
      <button type="button" :class="{ on: tab === 'secrets' }" @click="tab = 'secrets'">Secret scan</button>
      <button type="button" :class="{ on: tab === 'jwt' }" @click="tab = 'jwt'">JWT decode</button>
      <button type="button" :class="{ on: tab === 'hash' }" @click="tab = 'hash'">Hash</button>
    </nav>

    <section v-if="tab === 'password'" class="panel">
      <label>
        Password
        <input v-model="password" type="password" autocomplete="new-password" placeholder="Type to score…" />
      </label>
      <div class="meter">
        <i :style="{ width: pw.score + '%' }" :data-l="pw.label" />
      </div>
      <div class="scoreline">
        <b :data-l="pw.label">{{ pw.score }}</b>
        <span>{{ pw.label }}</span>
      </div>
      <ul class="checks">
        <li v-for="(ok, key) in pw.checks" :key="key" :data-ok="ok">{{ key }}</li>
      </ul>
    </section>

    <section v-else-if="tab === 'secrets'" class="panel">
      <label>
        Paste logs / config (never paste real production secrets)
        <textarea v-model="paste" rows="8" />
      </label>
      <p class="count">{{ scan?.count || 0 }} finding(s)</p>
      <div v-if="scan?.findings?.length" class="findings">
        <article v-for="(f, i) in scan.findings" :key="i">
          <strong>{{ f.label }}</strong>
          <code>{{ f.preview }}</code>
          <span>{{ f.length }} chars</span>
        </article>
      </div>
      <p v-else class="muted">No secret shapes detected.</p>
    </section>

    <section v-else-if="tab === 'jwt'" class="panel">
      <label>
        JWT
        <textarea v-model="jwt" rows="4" />
      </label>
      <button class="primary" type="button" @click="runJwt">Decode</button>
      <p v-if="jwtErr" class="err">{{ jwtErr }}</p>
      <pre v-if="jwtOut">{{ JSON.stringify(jwtOut, null, 2) }}</pre>
    </section>

    <section v-else class="panel">
      <label>
        Input
        <textarea v-model="hashInput" rows="3" />
      </label>
      <label>
        Algorithm
        <select v-model="hashAlgo">
          <option>SHA-256</option>
          <option>SHA-512</option>
          <option>SHA-1</option>
        </select>
      </label>
      <button class="primary" type="button" @click="runHash">Hash</button>
      <pre v-if="hashOut">{{ hashOut }}</pre>
    </section>
  </div>
</template>

<style scoped>
.shell {
  min-height: 100vh;
  padding: 22px clamp(14px, 3vw, 36px) 40px;
  max-width: 820px;
  margin: 0 auto;
  display: grid;
  gap: 16px;
}
header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: start;
  animation: rise .45s ease;
}
@keyframes rise {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: none; }
}
.eyebrow {
  margin: 0; color: var(--copper); letter-spacing: .12em; text-transform: uppercase; font-size: .72rem;
}
h1 {
  margin: 8px 0 0;
  font-family: var(--display);
  font-size: clamp(2.4rem, 6vw, 3.4rem);
  font-weight: 400;
  letter-spacing: -0.02em;
  line-height: 1;
}
.lede { margin: 12px 0 0; color: var(--muted); max-width: 36rem; line-height: 1.5; }
.seal {
  width: 72px; height: 72px; border-radius: 50%;
  border: 1px solid color-mix(in srgb, var(--copper) 45%, var(--line));
  background:
    radial-gradient(circle at 50% 40%, rgba(212,165,116,.35), transparent 55%),
    #1a1512;
  position: relative;
  flex-shrink: 0;
}
.seal::after {
  content: '';
  position: absolute; left: 50%; top: 28%; width: 18px; height: 18px;
  border: 2px solid var(--copper); border-radius: 50%; transform: translateX(-50%);
}
.tabs { display: flex; gap: 6px; flex-wrap: wrap; }
.tabs button {
  padding: 8px 12px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted);
}
.tabs button.on {
  color: var(--text);
  border-color: color-mix(in srgb, var(--copper) 45%, var(--line));
  background: color-mix(in srgb, var(--copper) 12%, transparent);
}
.panel {
  padding: 16px; border-radius: 16px; border: 1px solid var(--line); background: var(--panel);
  display: grid; gap: 12px; animation: rise .35s ease;
}
label { display: grid; gap: 6px; font-size: .8rem; color: var(--muted); }
input, textarea, select {
  width: 100%; padding: 11px 12px; border-radius: 10px; border: 1px solid var(--line);
  background: #120f0d; outline: none;
}
textarea { resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.meter {
  height: 10px; border-radius: 99px; background: #120f0d; overflow: hidden; border: 1px solid var(--line);
}
.meter i { display: block; height: 100%; transition: width .25s ease; background: var(--bad); }
.meter i[data-l='weak'] { background: #e0a24a; }
.meter i[data-l='fair'] { background: var(--copper); }
.meter i[data-l='strong'] { background: var(--ok); }
.scoreline { display: flex; gap: 10px; align-items: baseline; }
.scoreline b { font-size: 1.6rem; }
.scoreline b[data-l='critical'], .scoreline b[data-l='weak'] { color: var(--bad); }
.scoreline b[data-l='fair'] { color: var(--copper); }
.scoreline b[data-l='strong'] { color: var(--ok); }
.checks { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px; }
.checks li {
  font-size: .72rem; padding: 5px 8px; border-radius: 999px; border: 1px solid var(--line); color: var(--faint);
}
.checks li[data-ok='true'] { color: var(--ok); border-color: rgba(125,186,140,.35); }
.findings { display: grid; gap: 8px; }
.findings article {
  display: grid; grid-template-columns: 1fr auto auto; gap: 10px; align-items: center;
  padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: #120f0d;
}
.findings code { color: var(--copper); font-size: .8rem; }
.findings span { color: var(--faint); font-size: .75rem; }
.count { margin: 0; color: var(--copper); font-weight: 600; }
.muted { margin: 0; color: var(--faint); }
.primary {
  justify-self: start; padding: 10px 16px; border-radius: 999px; font-weight: 700;
  background: linear-gradient(180deg, #e0b888, #a67a4a); color: #1a120c;
}
pre {
  margin: 0; padding: 12px; border-radius: 12px; background: #120f0d; border: 1px solid var(--line);
  overflow: auto; font-size: .8rem; color: var(--muted); white-space: pre-wrap; word-break: break-all;
}
.err { margin: 0; color: var(--bad); }
@media (max-width: 600px) {
  .findings article { grid-template-columns: 1fr; }
}
</style>
