const fs = require('fs');
const crypto = require('crypto').webcrypto;

// Definição das constantes originais do Pippo
const LINK_LOCK_PASSWORD = "pippo";
const LINK_LOCK_HOST = "pippo26442999.github.io";
const LINK_LOCK_PATH_PREFIX = "/link-lock-pippo/";
const LINK_LOCK_VERSION = "0.0.1";
const LINK_LOCK_V2_PATH_PREFIX = "/library-decrypt/";
const LINK_LOCK_V2_ITERATIONS = 600000;
const LINK_LOCK_V2_DEFAULT_SALT_B64 = "AAAAAAAAAAAAAAAAAAAAAA";
const LINK_LOCK_V2_DEFAULT_IV_B64 = "AAAAAAAAAAAAAAAAAAAA";

const GROUP_ORDER = { files: 0, standard: 1, backport: 2, backport7xx: 3, backport4xx: 4, dlc: 5, dump: 6 };
const GROUP_LABELS = { files: "", standard: "Standard", backport: "BackPort", backport7xx: "7.xx BackPort", backport4xx: "4.xx BackPort", dlc: "DLC", dump: "Dump" };
const MIRROR_LABELS = { akia: "AkiraBox", akirabox: "AkiraBox", viki: "VikingFile", vikingfile: "VikingFile", data: "DataNodes", datanodes: "DataNodes", buzz: "BuzzHeavier", buzzheavier: "BuzzHeavier", medi: "MediaFire", mediafire: "MediaFire", gofi: "GoFile", gofile: "GoFile", pixe: "PixelDrain", pixeldrain: "PixelDrain", filek: "FileKeeper", filekeeper: "FileKeeper", vault: "DataVault", datavault: "DataVault" };

const TITLE_ID_RE = /\b([A-Z]{4}\d{5})\b/;
const VERSION_RE = /\bv\d+(?:\.\d+)+\b/i;
const SIZE_RE = /\b(?<value>\d+(?:[.,]\d+)?)\s*(?<unit>ki?b|mi?b|gi?b|ti?b)\b/i;
const SIZE_UNITS = { kb: 1024, kib: 1024, mb: 1024 ** 2, mib: 1024 ** 2, gb: 1024 ** 3, gib: 1024 ** 3, tb: 1024 ** 4, tib: 1024 ** 4 };

function base64ToBuffer(base64Str) {
  let normalized = base64Str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (normalized.length % 4)) % 4;
  normalized += '='.repeat(padding);
  const binaryString = atob(normalized);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function deriveKey(password, salt, iterations = 100000) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}

const _derivedKeyCache = new Map();
function _saltToB64(salt) {
  let s = '';
  for (let i = 0; i < salt.length; i++) s += String.fromCharCode(salt[i]);
  return btoa(s);
}

async function deriveKeyCached(password, salt, iterations = 100000) {
  const cacheKey = `${password}|${iterations}|${_saltToB64(salt)}`;
  if (_derivedKeyCache.has(cacheKey)) return _derivedKeyCache.get(cacheKey);
  const keyPromise = deriveKey(password, salt, iterations);
  _derivedKeyCache.set(cacheKey, keyPromise);
  return keyPromise;
}

async function decryptLinkLockV2Url(encryptedUrl) {
  const parsed = new URL(encryptedUrl);
  const compressed = JSON.parse(new TextDecoder().decode(base64ToBuffer(parsed.hash.slice(1))));
  const encrypted = base64ToBuffer(compressed.e);
  const salt = base64ToBuffer(compressed.s || LINK_LOCK_V2_DEFAULT_SALT_B64);
  const iv = base64ToBuffer(compressed.i || LINK_LOCK_V2_DEFAULT_IV_B64);
  const key = await deriveKeyCached(LINK_LOCK_PASSWORD, salt, LINK_LOCK_V2_ITERATIONS);
  const ciphertext = encrypted.slice(0, encrypted.length - 16);
  const tag = encrypted.slice(encrypted.length - 16);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, new Uint8Array([...ciphertext, ...tag]));
  const plaintext = new TextDecoder().decode(decrypted);
  try { const obj = JSON.parse(plaintext); if (obj && typeof obj.u === 'string') return obj.u; } catch {}
  return plaintext;
}

async function decryptLinkLockUrl(encryptedUrl) {
  const probe = new URL(encryptedUrl);
  if (probe.hostname === LINK_LOCK_HOST && probe.pathname.startsWith(LINK_LOCK_V2_PATH_PREFIX)) {
    return decryptLinkLockV2Url(encryptedUrl);
  }
  const parsed = new URL(encryptedUrl);
  const payload = base64ToBuffer(parsed.hash.slice(1));
  const params = JSON.parse(new TextDecoder().decode(payload));
  const encrypted = base64ToBuffer(params.e);
  const salt = params.s ? base64ToBuffer(params.s) : new Uint8Array([236, 231, 167, 249, 207, 95, 201, 235, 164, 98, 246, 26, 176, 174, 72, 249]);
  const iv = params.i ? base64ToBuffer(params.i) : new Uint8Array([255, 237, 148, 105, 6, 255, 123, 202, 115, 130, 16, 116]);
  const key = await deriveKeyCached(LINK_LOCK_PASSWORD, salt);
  const ciphertext = encrypted.slice(0, encrypted.length - 16);
  const tag = encrypted.slice(encrypted.length - 16);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, new Uint8Array([...ciphertext, ...tag]));
  return new TextDecoder().decode(decrypted);
}

function isLinkLockUrl(value) {
  try {
    const parsed = new URL(value);
    if (parsed.hostname !== LINK_LOCK_HOST) return false;
    return parsed.pathname.startsWith(LINK_LOCK_PATH_PREFIX) || parsed.pathname.startsWith(LINK_LOCK_V2_PATH_PREFIX);
  } catch { return false; }
}

function cleanString(value) { return typeof value === 'string' ? value.replace(/\u00a0/g, ' ').split(/\s+/).join(' ').trim() : ''; }
function cleanTags(value) { return Array.isArray(value) ? value.map(cleanString).filter(Boolean) : []; }
function titleIdFromTags(tags) { for (const tag of tags) { const match = tag.match(TITLE_ID_RE); if (match) return match[1]; } return null; }
function versionFromTags(tags) { for (const tag of tags) { const match = tag.match(VERSION_RE); if (match) return match[0]; } return null; }
function parseSizeBytes(text) { if (!text) return null; const match = text.match(SIZE_RE); if (!match) return null; const value = parseFloat(match.groups.value.replace(',', '.')); const unit = match.groups.unit.toLowerCase(); return Math.trunc(value * (SIZE_UNITS[unit] || 0)); }
function formatLabel(value) { return value.split(/[_\s-]+/).filter(Boolean).map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join(' '); }
function splitLinkKey(key) { if (key.endsWith('_url')) return ['files', key.slice(0, -'_url'.length)]; const index = key.lastIndexOf('_'); if (index !== -1) return [key.slice(0, index) || 'files', key.slice(index + 1)]; return ['files', key]; }
function backportFirmwareFromTags(tags) { for (const tag of tags) { const m = tag.match(/(\d\.x{1,2})\s*backpor[kt]/i); if (m) return m[1].toLowerCase(); } return ''; }
function standardFirmwareFromTags(tags) { for (const tag of tags) { const m = tag.match(/standard\s*\(?\s*(\d\.x{1,2})/i); if (m) return m[1].toLowerCase(); } for (const tag of tags) { const m = tag.match(/(\d\.x{1,2})\s*and\s*beyond/i); if (m) return m[1].toLowerCase(); } return ''; }
function linkName(mirror, group) { const mirrorLabel = MIRROR_LABELS[mirror.toLowerCase()] || formatLabel(mirror); const groupLabel = GROUP_LABELS[group] || formatLabel(group); if (!groupLabel || group === 'files') return mirrorLabel; return `${groupLabel} - ${mirrorLabel}`; }
function descriptionAll(item, builds) { const lines = []; const tags = cleanTags(item.tags); const size = cleanString(item.size); const howToPlay = cleanString(item.how_to_play); if (builds && builds.length) lines.push(`Builds: ${builds.join(', ')}`); if (tags.length) lines.push(`Tags: ${tags.join(', ')}`); if (size) lines.push(`Size: ${size}`); const credits = []; if (item.credits_files) credits.push(`Files: ${item.credits_files}`); if (item.credits_backport) credits.push(`Backport: ${item.credits_backport}`); if (item.credits_dlc || item.credits_dlcs) credits.push(`DLC: ${item.credits_dlc || item.credits_dlcs}`); if (credits.length) lines.push(`Credits: ${credits.join('; ')}`); if (howToPlay) lines.push(`How to play: ${howToPlay}`); return lines.length ? lines.join('\n') : null; }

async function packagesForItem(item, itemNumber, warnings) {
  const packages = [];
  const title = cleanString(item.title);
  const tags = cleanTags(item.tags);
  const titleId = titleIdFromTags(tags);
  if (!title || !titleId) return packages;

  const groupedLinks = new Map();
  const seen = new Set();

  for (const [key, value] of Object.entries(item)) {
    if (typeof value !== 'string' || !isLinkLockUrl(value)) continue;
    const [group, mirror] = splitLinkKey(key);
    let decodedUrl;
    try { decodedUrl = await decryptLinkLockUrl(value); } catch (error) { continue; }
    const name = linkName(mirror, group);
    const dedupeKey = `${group}\0${name.toLowerCase()}\0${decodedUrl}`;
    if (seen.has(dedupeKey)) continue;
    if (!groupedLinks.has(group)) groupedLinks.set(group, []);
    groupedLinks.get(group).push({ name, url: decodedUrl });
    seen.add(dedupeKey);
  }

  const sortedGroups = [...groupedLinks.entries()].sort(([leftGroup], [rightGroup]) => {
    const leftOrder = GROUP_ORDER[leftGroup] ?? 100;
    const rightOrder = GROUP_ORDER[rightGroup] ?? 100;
    return leftOrder !== rightOrder ? leftOrder - rightOrder : leftGroup.localeCompare(rightGroup);
  }).filter(([, links]) => links.length);

  const stdFw = standardFirmwareFromTags(tags);
  const bpFw = backportFirmwareFromTags(tags);
  const allLinks = [];
  const buildLabels = [];
  let onlyDlc = true;

  for (const [group, links] of sortedGroups) {
    if (group !== 'dlc') onlyDlc = false;
    let groupLabel = GROUP_LABELS[group] || formatLabel(group);
    if (group === 'standard' && stdFw) groupLabel = `Standard ${stdFw}`;
    if (group === 'backport' && bpFw) groupLabel = `${bpFw} BackPort`;
    for (const link of links) {
      if (group === 'standard' && stdFw && link.name.startsWith('Standard - ')) link.name = link.name.replace(/^Standard - /, `Standard ${stdFw} - `);
      if (group === 'backport' && bpFw && link.name.startsWith('BackPort - ')) link.name = link.name.replace(/^BackPort - /, `${bpFw} BackPort - `);
      allLinks.push(link);
    }
    const disp = (group === 'files' || !groupLabel) ? 'Game' : groupLabel;
    if (!buildLabels.includes(disp)) buildLabels.push(disp);
  }
  if (!allLinks.length) return packages;

  packages.push({
    titleId,
    title,
    version: versionFromTags(tags) || null,
    category: onlyDlc ? 'dlc' : 'game',
    posterUrl: cleanString(item.image) || null,
    description: descriptionAll(item, buildLabels.filter(b => b !== 'Game')),
    downloadLinks: allLinks,
    sizeBytes: parseSizeBytes(cleanString(item.size))
  });
  return packages;
}

async function convertExFatToPegasus(exFatData) {
  const allPackages = [];
  for (let i = 0; i < exFatData.length; i++) {
    const packages = await packagesForItem(exFatData[i], i + 1, []);
    allPackages.push(...packages);
  }
  return {
    catalog: {
      name: "exFAT Ripper",
      version: 1,
      packages: allPackages,
      _generated: new Date().toISOString()
    }
  };
}

// EXECUÇÃO DO SCRIPT NO AMBIENTE AUTOMAÇÃO
// EXECUÇÃO DO SCRIPT NO AMBIENTE AUTOMAÇÃO
// EXECUÇÃO DO SCRIPT NO AMBIENTE AUTOMAÇÃO
async function autoUpdate() {
  try {
    // Usando a URL direta que descobrimos!
    const URL_ORIGINAL = "https://pippo26442999.github.io/.exFAT/exFAT.json"; 
    
    console.log("Baixando o catálogo bruto do exFAT.json...");
    const response = await fetch(URL_ORIGINAL);
    
    if (!response.ok) {
      throw new Error(`Erro ao baixar arquivo (${response.status}): ${response.statusText}`);
    }
    
    const exFatData = await response.json();
    console.log("Catálogo obtido! Convertendo para o formato do Pegasus DL...");

    globalThis.crypto = crypto; 
    const resultado = await convertExFatToPegasus(exFatData);

    // Salva o arquivo final convertido
    fs.writeFileSync('lista_ps5.json', JSON.stringify(resultado.catalog, null, 2));
    console.log("Sucesso! O arquivo lista_ps5.json formatado para Pegasus foi gerado.");
  } catch (error) {
    console.error("Erro na conversão:", error.message);
    process.exit(1);
  }
}

autoUpdate();
