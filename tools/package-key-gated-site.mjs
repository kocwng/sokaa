import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = resolve(root, 'site-source.html');
const outputPath = resolve(root, 'index.html');
const iterations = 600_000;

function readSecret(prompt) {
  return new Promise((resolvePromise, reject) => {
    if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') {
      reject(new Error('Jalankan lewat terminal interaktif agar key tidak tampil atau tersimpan.'));
      return;
    }
    process.stdout.write(prompt);
    let value = '';
    const onData = (chunk) => {
      for (const byte of chunk) {
        if (byte === 3) {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdout.write('\nDibatalkan.\n');
          process.exit(130);
        }
        if (byte === 13 || byte === 10) {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolvePromise(value);
          return;
        }
        if (byte === 127 || byte === 8) value = value.slice(0, -1);
        else if (byte >= 32) value += Buffer.from([byte]).toString('utf8');
      }
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

const key = await readSecret('Buat key akses (minimal 16 karakter; tidak akan ditampilkan/disimpan): ');
if (Buffer.byteLength(key, 'utf8') < 16) {
  process.stderr.write('Key terlalu pendek. Jalankan ulang dan gunakan minimal 16 karakter.\n');
  process.exit(1);
}
if (!/^[\x20-\x7E]+$/.test(key)) {
  process.stderr.write('Gunakan karakter ASCII agar key dapat diketik konsisten di semua perangkat.\n');
  process.exit(1);
}
const confirm = await readSecret('Ulangi key: ');
if (key !== confirm) {
  process.stderr.write('Key tidak cocok. Jalankan ulang.\n');
  process.exit(1);
}

const plaintext = await readFile(sourcePath);
const salt = randomBytes(16);
const iv = randomBytes(12);
const derived = pbkdf2Sync(key, salt, iterations, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', derived, iv);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
const payload = JSON.stringify({ salt: salt.toString('base64'), iv: iv.toString('base64'), iterations, data: encrypted.toString('base64') });

const wrapper = `<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#07120f"><title>Masukkan key — KickOff</title>
<style>:root{color-scheme:dark;font:16px system-ui,sans-serif;background:#07120f;color:#f3f7f4}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:20px}.box{width:min(390px,100%);padding:28px;border:1px solid #26362f;border-radius:18px;background:#101d18;box-shadow:0 24px 80px #0008}h1{margin:0 0 8px;font-size:24px}.hint{margin:0 0 20px;color:#94a79d;line-height:1.55;font-size:14px}label{display:block;margin-bottom:7px;font-size:13px}input{width:100%;padding:12px;border:1px solid #405347;border-radius:9px;background:#07120f;color:#fff;font:inherit}button{width:100%;margin-top:12px;padding:12px;border:0;border-radius:9px;background:#c9f36a;color:#12200f;font:700 14px system-ui,sans-serif;cursor:pointer}button:disabled{opacity:.6;cursor:wait}.error{min-height:1.4em;margin-top:10px;color:#ff9b93;font-size:13px}.foot{margin-top:14px;color:#74857b;font-size:11px}</style></head>
<body><form class="box" id="gate"><h1>KickOff</h1><p class="hint">Masukkan key akses untuk membuka situs.</p><label for="key">Key</label><input id="key" type="password" autocomplete="current-password" required autofocus><button id="submit" type="submit">Buka situs</button><div id="error" class="error" role="alert"></div><div class="foot">Key tidak disimpan pada perangkat ini.</div></form>
<script>
const PAYLOAD=${payload};
const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const form=document.getElementById('gate'), field=document.getElementById('key'), button=document.getElementById('submit'), error=document.getElementById('error');
form.addEventListener('submit',async event=>{event.preventDefault();button.disabled=true;error.textContent='Memeriksa key…';try{const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(field.value),'PBKDF2',false,['deriveKey']);const aes=await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode(PAYLOAD.salt),iterations:PAYLOAD.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(PAYLOAD.iv)},aes,decode(PAYLOAD.data));const html=new TextDecoder().decode(clear);field.value='';document.open();document.write(html);document.close()}catch(_){field.value='';error.textContent='Key salah. Coba lagi.';button.disabled=false;field.focus()}});
</script></body></html>`;
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, wrapper, { mode: 0o644 });
process.stdout.write(`Paket terkunci dibuat: ${outputPath}\nKey tidak disimpan. Jangan commit site-source.html; file itu masuk .gitignore.\n`);
