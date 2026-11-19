'use strict';
/* Coffre mobile — tout reste sur l'appareil (IndexedDB), chiffré en AES-GCM 256.
   Clé du coffre aléatoire, emballée deux fois : par le mot de passe et par le code de secours (PBKDF2-SHA256). */

const VERSION = 1;
const ITER = 310000;
const TAILLE_MAX = 700 * 1024 * 1024;
const $ = (s, r = document) => r.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();

let cle = null, cleBrute = null, index = null;
const etat = { dossier: null, recherche: '', selection: null, liste: [], vue: -1 };
const urlsMini = new Map();
const cacheOrig = new Map(); // id -> {url, blob}
let reglages = Object.assign({ verrou: 30, inactivite: 300, viderPP: true }, lireReglages());

/* ---------- Petits outils ---------- */
function lireReglages() { try { return JSON.parse(localStorage.getItem('coffre-reglages')) || {}; } catch { return {}; } }
function sauverReglages() { try { localStorage.setItem('coffre-reglages', JSON.stringify(reglages)); } catch {} }
const alea = n => crypto.getRandomValues(new Uint8Array(n));
const uid = () => [...alea(9)].map(x => x.toString(16).padStart(2, '0')).join('');
function b64(u) { u = u instanceof Uint8Array ? u : new Uint8Array(u); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
const deb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const normaliser = s => (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
function taille(n) { if (n < 1024) return n + ' o'; if (n < 1048576) return (n / 1024).toFixed(0) + ' Ko'; if (n < 1073741824) return (n / 1048576).toFixed(1).replace('.', ',') + ' Mo'; return (n / 1073741824).toFixed(2).replace('.', ',') + ' Go'; }
function duree(s) { if (!isFinite(s)) return ''; s = Math.round(s); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }
function attendre(el, ev, ms) {
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('délai')), ms);
    el.addEventListener(ev, () => { clearTimeout(t); res(); }, { once: true });
    el.addEventListener('error', () => { clearTimeout(t); rej(new Error('erreur')); }, { once: true });
  });
}
let toastT;
function toast(t, ms = 2600) { const e = $('#toast'); e.textContent = t; e.hidden = false; clearTimeout(toastT); if (ms) toastT = setTimeout(() => e.hidden = true, ms); }
function montrer(id) { document.querySelectorAll('.ecran').forEach(e => e.hidden = e.id !== id); }

/* ---------- Base locale ---------- */
let dbP;
function db() {
  return dbP ||= new Promise((res, rej) => {
    const r = indexedDB.open('coffre', 1);
    r.onupgradeneeded = () => { r.result.createObjectStore('meta'); r.result.createObjectStore('fichiers'); };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(store, mode); let out;
    const r = fn(t.objectStore(store));
    if (r) r.onsuccess = () => { out = r.result; };
    t.oncomplete = () => res(out);
    t.onerror = t.onabort = () => rej(t.error || new Error('Écriture impossible (espace plein ?)'));
  });
}
const lire = (st, k) => tx(st, 'readonly', s => s.get(k));
const ecrire = (st, k, v) => tx(st, 'readwrite', s => { s.put(v, k); });
const effacer = (st, k) => tx(st, 'readwrite', s => { s.delete(k); });
const toutesCles = st => tx(st, 'readonly', s => s.getAllKeys());
const toutVider = () => Promise.all(['meta', 'fichiers'].map(st => tx(st, 'readwrite', s => { s.clear(); })));

/* ---------- Chiffrement ---------- */
async function deriver(secret, sel, iter = ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: sel, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function chiffrer(k, donnees, aad) {
  const iv = alea(12);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, k, donnees);
  return { iv, data };
}
async function dechiffrer(k, rec, aad) {
  const data = rec.data instanceof Blob ? await rec.data.arrayBuffer() : rec.data;
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: enc.encode(aad) }, k, data);
}
const ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genererCode() {
  let s = '';
  while (s.length < 20) for (const x of alea(32)) if (x < 248 && s.length < 20) s += ALPHA[x % 31];
  return s.match(/.{4}/g).join('-');
}
const normCode = s => (s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

async function creerCoffre(mdp) {
  const brut = alea(32), code = genererCode(), sm = alea(16), ss = alea(16);
  const meta = { v: 1, iter: ITER, sm, ss,
    cm: await chiffrer(await deriver(mdp, sm), brut, 'cle'),
    cs: await chiffrer(await deriver(normCode(code), ss), brut, 'cle') };
  await ecrire('meta', 'coffre', meta);
  await installerCle(brut);
  index = { dossiers: [], elements: [], tags: [] };
  await sauverIndex();
  navigator.storage?.persist?.().catch(() => {});
  return code;
}
async function installerCle(brut) {
  cleBrute = brut;
  cle = await crypto.subtle.importKey('raw', brut, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function ouvrirCoffre(secret, parSecours) {
  const meta = await lire('meta', 'coffre');
  const k = await deriver(parSecours ? normCode(secret) : secret, parSecours ? meta.ss : meta.sm, meta.iter);
  let brut;
  try { brut = new Uint8Array(await dechiffrer(k, parSecours ? meta.cs : meta.cm, 'cle')); }
  catch { throw new Error(parSecours ? 'Code de secours incorrect' : 'Mot de passe incorrect'); }
  await installerCle(brut);
  const ri = await lire('meta', 'index');
  index = ri ? JSON.parse(dec.decode(await dechiffrer(cle, ri, 'index'))) : { dossiers: [], elements: [] };
  index.tags ||= [];
}
async function changerMdp(mdp) {
  const meta = await lire('meta', 'coffre');
  meta.sm = alea(16); meta.iter = ITER;
  meta.cm = await chiffrer(await deriver(mdp, meta.sm), cleBrute, 'cle');
  await ecrire('meta', 'coffre', meta);
}
async function changerCode() {
  const meta = await lire('meta', 'coffre'), code = genererCode();
  meta.ss = alea(16);
  meta.cs = await chiffrer(await deriver(normCode(code), meta.ss, meta.iter), cleBrute, 'cle');
  await ecrire('meta', 'coffre', meta);
  return code;
}
let fileSauve = Promise.resolve();
function sauverIndex() {
  fileSauve = fileSauve.then(async () => {
    if (!cle) return;
    await ecrire('meta', 'index', await chiffrer(cle, enc.encode(JSON.stringify(index)), 'index'));
  }).catch(e => toast('Erreur d’enregistrement : ' + e.message, 6000));
  return fileSauve;
}

function verrouiller() {
  cle = null; cleBrute?.fill(0); cleBrute = null; index = null;
  for (const u of urlsMini.values()) URL.revokeObjectURL(u);
  for (const o of cacheOrig.values()) URL.revokeObjectURL(o.url);
  urlsMini.clear(); cacheOrig.clear();
  fermerVisionneuse(true);
  document.querySelectorAll('dialog[open]').forEach(d => d.close());
  $('#grille').textContent = ''; $('#dossiers').textContent = '';
  etat.selection = null; etat.dossier = null; etat.recherche = ''; $('#recherche').value = '';
  $('#o-mdp').value = ''; $('#o-erreur').textContent = ''; $('#toast').hidden = true;
  modeSecours(false);
  montrer('e-ouvrir');
}

/* ---------- Ajout de fichiers ---------- */
function genre(f) {
  const t = f.type || '';
  if (t.startsWith('image/')) return 'image';
  if (t.startsWith('video/')) return 'video';
  const e = (f.name || '').toLowerCase().split('.').pop();
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'heif', 'avif', 'bmp'].includes(e)) return 'image';
  if (['mp4', 'mov', 'm4v', 'webm'].includes(e)) return 'video';
  return null;
}
async function faireMiniature(blob, g) {
  const url = URL.createObjectURL(blob);
  try {
    let src, l, h, d;
    if (g === 'image') {
      const im = new Image(); im.src = url; await im.decode();
      src = im; l = im.naturalWidth; h = im.naturalHeight;
    } else {
      const v = document.createElement('video');
      v.muted = true; v.playsInline = true; v.preload = 'auto'; v.src = url;
      await attendre(v, 'loadeddata', 10000);
      d = v.duration;
      v.currentTime = Math.min(0.5, (v.duration || 1) / 2);
      await attendre(v, 'seeked', 5000).catch(() => {});
      src = v; l = v.videoWidth; h = v.videoHeight;
    }
    const M = 480, r = Math.min(1, M / Math.max(l, h, 1));
    const c = document.createElement('canvas');
    c.width = Math.max(1, Math.round(l * r)); c.height = Math.max(1, Math.round(h * r));
    c.getContext('2d').drawImage(src, 0, 0, c.width, c.height);
    const mini = await new Promise(res => c.toBlob(res, 'image/jpeg', 0.82));
    return { mini, l, h, d };
  } catch { return { mini: null }; }
  finally { URL.revokeObjectURL(url); }
}
async function ajouterUn(f, dossier) {
  const g = genre(f);
  if (!g) throw new Error('format non pris en charge');
  if (f.size > TAILLE_MAX) throw new Error('fichier trop gros (' + taille(f.size) + ')');
  const buf = await f.arrayBuffer();
  const id = uid();
  const { mini, l, h, d } = await faireMiniature(new Blob([buf], { type: f.type }), g);
  const o = await chiffrer(cle, buf, id + ':o');
  await ecrire('fichiers', id + ':o', { iv: o.iv, data: new Blob([o.data]) });
  if (mini) {
    const m = await chiffrer(cle, await mini.arrayBuffer(), id + ':m');
    await ecrire('fichiers', id + ':m', { iv: m.iv, data: new Blob([m.data]) });
  }
  index.elements.push({ id, type: g, mime: f.type || '', nom: f.name || '', taille: buf.byteLength,
    l: l || 0, h: h || 0, duree: d || 0, dossier, tags: [], ajoute: Date.now(), mini: !!mini });
}
let ajoutEnCours = false;
async function ajouterFichiers(liste) {
  liste = [...liste].filter(Boolean);
  if (!liste.length || !cle) return 0;
  ajoutEnCours = true;
  const dossier = etat.dossier;
  let ok = 0; const erreurs = [];
  for (let i = 0; i < liste.length; i++) {
    if (liste.length > 1) toast(`Ajout ${i + 1} / ${liste.length}…`, 0);
    try { await ajouterUn(liste[i], dossier); ok++; }
    catch (e) { erreurs.push((liste[i].name || 'image') + ' : ' + e.message); }
    if (!cle) break;
  }
  ajoutEnCours = false;
  if (!cle) return ok;
  await sauverIndex();
  rendre();
  toast(erreurs.length ? `${ok} ajouté(s). ${erreurs.join(' · ')}` : (ok > 1 ? `${ok} ajoutés au coffre` : 'Ajouté au coffre'), erreurs.length ? 6000 : 2200);
  return ok;
}
function extension(mime) { return ({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp', 'image/heic': 'heic', 'video/mp4': 'mp4', 'video/quicktime': 'mov' })[mime] || 'bin'; }

async function coller() {
  if (!navigator.clipboard?.read) return ouvrirZoneColler();
  let items;
  try { items = await navigator.clipboard.read(); }
  catch { return ouvrirZoneColler(); }
  const fichiers = [];
  for (const it of items) {
    const t = it.types.find(x => x.startsWith('image/')) || it.types.find(x => x.startsWith('video/'));
    if (!t) continue;
    const b = await it.getType(t);
    fichiers.push(new File([b], 'colle-' + Date.now() + '.' + extension(t), { type: t }));
  }
  if (!fichiers.length) {
    // Le presse-papiers ne contient pas d'image, mais peut-être une adresse d'image
    const texte = (await navigator.clipboard.readText().catch(() => '')).trim();
    if (/^https?:\/\//.test(texte)) return importerAdresse(texte);
    return toast('Pas d’image dans le presse-papiers. Fais un appui long sur l’image → Copier.', 4500);
  }
  const n = await ajouterFichiers(fichiers);
  if (n && reglages.viderPP) navigator.clipboard.writeText(' ').catch(() => {});
}
function ouvrirZoneColler() {
  const z = $('#zone-coller'); z.textContent = '';
  $('#d-coller').showModal();
}
async function fichiersDepuis(dt) {
  const out = [];
  for (const f of dt.files || []) out.push(f);
  if (!out.length) for (const it of dt.items || []) if (it.kind === 'file') { const f = it.getAsFile(); if (f) out.push(f); }
  if (!out.length) {
    const html = dt.getData?.('text/html') || '';
    const src = (html.match(/<img[^>]+src="([^"]+)"/i) || [])[1];
    const url = src || dt.getData?.('text/uri-list') || dt.getData?.('text/plain') || '';
    if (/^(https?:|data:image)/.test(url.trim())) {
      const f = await telecharger(url.trim()).catch(() => null);
      if (f) out.push(f); else toast('Ce site bloque la copie de son image. Utilise Copier puis Coller.', 4500);
    }
  }
  return out;
}
async function telecharger(url) {
  const r = await fetch(url, { mode: 'cors', referrerPolicy: 'no-referrer' });
  if (!r.ok) throw new Error(r.status);
  const b = await r.blob();
  if (!genre(b)) throw new Error('pas une image');
  return new File([b], 'web-' + Date.now() + '.' + extension(b.type), { type: b.type });
}
async function importerAdresse(url) {
  try { await ajouterFichiers([await telecharger(url)]); }
  catch { toast('Impossible de récupérer cette adresse. Copie l’image elle-même.', 4500); }
}

/* ---------- Dossiers & recherche ---------- */
const dossierPar = id => index.dossiers.find(d => d.id === id);
const enfants = id => index.dossiers.filter(d => d.parent === id).sort((a, b) => a.nom.localeCompare(b.nom, 'fr'));
function cheminDossier(id) { const r = []; let d = dossierPar(id); while (d) { r.unshift(d); d = dossierPar(d.parent); } return r; }
function descendants(id) {
  const s = new Set([id]); let change = true;
  while (change) { change = false; for (const d of index.dossiers) if (s.has(d.parent) && !s.has(d.id)) { s.add(d.id); change = true; } }
  return s;
}
function creerDossier(nom, parent) { const d = { id: uid(), nom: nom.trim(), parent, cree: Date.now() }; index.dossiers.push(d); return d; }
function mots(t) { return normaliser(t).split(/[\s,._\-/]+/).filter(Boolean); }
function correspond(e, q) {
  const w = [...(e.tags || []).flatMap(mots), ...cheminDossier(e.dossier).flatMap(d => mots(d.nom)), ...mots(e.nom)];
  return q.every(m => w.some(x => x.startsWith(m)));
}

/* ---------- Affichage ---------- */
const observateur = new IntersectionObserver(entrees => {
  for (const en of entrees) if (en.isIntersecting) { observateur.unobserve(en.target); remplirMini(en.target); }
}, { rootMargin: '400px' });

async function urlMini(id) {
  if (urlsMini.has(id)) return urlsMini.get(id);
  const rec = await lire('fichiers', id + ':m');
  if (!rec || !cle) return null;
  const buf = await dechiffrer(cle, rec, id + ':m');
  if (!cle) return null;
  const u = URL.createObjectURL(new Blob([buf], { type: 'image/jpeg' }));
  urlsMini.set(id, u);
  return u;
}
async function remplirMini(el) {
  const img = el.querySelector('img');
  try { const u = await urlMini(el.dataset.id); if (u && img.isConnected) { img.onload = () => img.classList.add('pret'); img.src = u; } } catch {}
}

function rendre() {
  if (!index) return;
  const q = mots(etat.recherche);
  // chemin
  const ch = $('#chemin'); ch.textContent = '';
  const lien = (t, id) => { const b = document.createElement('button'); b.textContent = t; b.onclick = () => allerA(id); return b; };
  if (q.length) { const s = document.createElement('span'); s.textContent = 'Recherche'; ch.append(s); }
  else {
    ch.append(lien('Coffre', null));
    for (const d of cheminDossier(etat.dossier)) { const s = document.createElement('span'); s.className = 'sep'; s.textContent = '›'; ch.append(s, lien(d.nom, d.id)); }
    requestAnimationFrame(() => ch.scrollLeft = ch.scrollWidth);
  }
  $('#b-retour').hidden = etat.dossier === null || q.length > 0;
  $('#b-menu-dossier').hidden = etat.dossier === null || q.length > 0;

  let elems, dossiers;
  if (q.length) {
    elems = index.elements.filter(e => correspond(e, q));
    dossiers = index.dossiers.filter(d => q.every(m => mots(d.nom).some(w => w.startsWith(m))));
  } else {
    elems = index.elements.filter(e => e.dossier === etat.dossier);
    dossiers = enfants(etat.dossier);
  }
  elems.sort((a, b) => b.ajoute - a.ajoute);
  etat.liste = elems;

  const zd = $('#dossiers'); zd.textContent = '';
  for (const d of dossiers) zd.append(carteDossier(d));

  const g = $('#grille'); g.textContent = '';
  const frag = document.createDocumentFragment();
  elems.forEach((e, i) => {
    const b = document.createElement('button');
    b.className = 'vignette'; b.dataset.id = e.id; b.dataset.i = i;
    if (etat.selection?.has(e.id)) b.classList.add('choisi');
    const img = document.createElement('img'); img.alt = ''; img.draggable = false; b.append(img);
    if (e.type === 'video') { const s = document.createElement('span'); s.className = 'duree'; s.textContent = duree(e.duree); b.append(s); }
    frag.append(b); observateur.observe(b);
  });
  g.append(frag);
  $('#vide').hidden = elems.length > 0 || dossiers.length > 0;
  $('#contenu').classList.toggle('selection', !!etat.selection);
  majBas();
}
function carteDossier(d) {
  const b = document.createElement('button'); b.className = 'carte-dossier';
  const ids = descendants(d.id);
  const dedans = index.elements.filter(e => ids.has(e.dossier));
  const recent = dedans.filter(e => e.mini).sort((a, b) => b.ajoute - a.ajoute)[0];
  if (recent) { const img = document.createElement('img'); img.alt = ''; b.append(img); urlMini(recent.id).then(u => { if (u) img.src = u; }).catch(() => {}); }
  else b.classList.add('sans-image');
  const et = document.createElement('span'); et.className = 'etiquette';
  const n = document.createElement('span'); n.className = 'nom'; n.textContent = d.nom;
  const c = document.createElement('span'); c.className = 'nb'; c.textContent = dedans.length + (dedans.length > 1 ? ' éléments' : ' élément');
  et.append(n, c); b.append(et);
  b.onclick = () => allerA(d.id);
  return b;
}
function allerA(id) {
  etat.dossier = id; etat.recherche = ''; $('#recherche').value = '';
  rendre(); scrollTo(0, 0);
}
function majBas() {
  const sel = !!etat.selection;
  $('#bas-normal').hidden = sel; $('#bas-selection').hidden = !sel;
  if (sel) $('#s-nombre').textContent = etat.selection.size;
}

/* ---------- Grille : toucher, appui long, sélection ---------- */
let appuiT = null, appuiLong = false;
$('#grille').addEventListener('pointerdown', ev => {
  const v = ev.target.closest('.vignette'); if (!v) return;
  appuiLong = false;
  clearTimeout(appuiT);
  appuiT = setTimeout(() => {
    appuiLong = true;
    if (!etat.selection) etat.selection = new Set();
    etat.selection.add(v.dataset.id); v.classList.add('choisi');
    $('#contenu').classList.add('selection'); majBas();
    navigator.vibrate?.(15);
  }, 480);
});
['pointerup', 'pointercancel', 'pointerleave'].forEach(t => $('#grille').addEventListener(t, () => clearTimeout(appuiT)));
$('#grille').addEventListener('scroll', () => clearTimeout(appuiT), true);
addEventListener('scroll', () => clearTimeout(appuiT), { passive: true });
$('#grille').addEventListener('contextmenu', ev => ev.preventDefault());
$('#grille').addEventListener('click', ev => {
  const v = ev.target.closest('.vignette'); if (!v) return;
  if (appuiLong) { appuiLong = false; return; }
  if (etat.selection) {
    const id = v.dataset.id;
    if (etat.selection.has(id)) { etat.selection.delete(id); v.classList.remove('choisi'); } else { etat.selection.add(id); v.classList.add('choisi'); }
    majBas();
  } else ouvrirVisionneuse(+v.dataset.i);
});

/* ---------- Visionneuse ---------- */
async function original(e) {
  if (cacheOrig.has(e.id)) { const o = cacheOrig.get(e.id); cacheOrig.delete(e.id); cacheOrig.set(e.id, o); return o; }
  const rec = await lire('fichiers', e.id + ':o');
  const buf = await dechiffrer(cle, rec, e.id + ':o');
  const blob = new Blob([buf], { type: e.mime || (e.type === 'video' ? 'video/mp4' : 'image/jpeg') });
  const o = { url: URL.createObjectURL(blob), blob };
  cacheOrig.set(e.id, o);
  while (cacheOrig.size > 4) { const [k, v] = cacheOrig.entries().next().value; cacheOrig.delete(k); URL.revokeObjectURL(v.url); }
  return o;
}
const zoom = { s: 1, x: 0, y: 0 };
function appliquerZoom() {
  const img = $('#v-scene img'); if (!img) return;
  img.style.transform = zoom.s === 1 ? '' : `translate(${zoom.x}px,${zoom.y}px) scale(${zoom.s})`;
}
function ouvrirVisionneuse(i) {
  $('#visionneuse').hidden = false; $('#visionneuse').classList.remove('nu');
  afficher(i);
}
function fermerVisionneuse(silencieux) {
  const v = $('#visionneuse'); if (v.hidden) return;
  v.hidden = true; $('#v-scene').textContent = ''; $('#v-info').hidden = true; etat.vue = -1;
  if (!silencieux) rendre();
}
async function afficher(i) {
  const L = etat.liste; if (!L.length) return fermerVisionneuse();
  i = Math.max(0, Math.min(L.length - 1, i)); etat.vue = i;
  const e = L[i];
  zoom.s = 1; zoom.x = 0; zoom.y = 0;
  $('#v-pos').textContent = `${i + 1} / ${L.length}`;
  const sc = $('#v-scene'); sc.innerHTML = '<span class="chargement">…</span>';
  majInfo();
  try {
    const o = await original(e);
    if (etat.vue !== i || $('#visionneuse').hidden) return;
    sc.textContent = '';
    if (e.type === 'video') {
      const v = document.createElement('video'); v.src = o.url; v.controls = true; v.playsInline = true; v.loop = true;
      sc.append(v);
    } else {
      const img = document.createElement('img'); img.src = o.url; img.draggable = false; img.alt = '';
      img.onload = () => { const r = img.getBoundingClientRect(); img.dataset.l = r.width; img.dataset.h = r.height; };
      sc.append(img);
    }
    // préchargement des voisines
    for (const j of [i + 1, i - 1]) if (L[j] && L[j].type === 'image') original(L[j]).catch(() => {});
  } catch (err) { sc.innerHTML = '<span class="chargement">Impossible d’ouvrir ce fichier.</span>'; }
}
function majInfo() {
  const e = etat.liste[etat.vue]; if (!e) return;
  const lignes = [];
  if (e.nom) lignes.push(e.nom);
  lignes.push(new Date(e.ajoute).toLocaleString('fr-FR', { dateStyle: 'long', timeStyle: 'short' }));
  lignes.push([e.l && e.h ? `${e.l} × ${e.h}` : '', taille(e.taille), e.type === 'video' ? duree(e.duree) : ''].filter(Boolean).join(' · '));
  const ch = cheminDossier(e.dossier).map(d => d.nom).join(' › ');
  lignes.push('Dossier : ' + (ch || 'non rangé'));
  if (e.tags?.length) lignes.push('Tags : ' + e.tags.join(', '));
  $('#v-info').innerHTML = lignes.map(l => `<div>${l.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c])}</div>`).join('');
}
$('#v-fermer').onclick = () => fermerVisionneuse();
$('#v-info-b').onclick = () => { $('#v-info').hidden = !$('#v-info').hidden; };

// Gestes : glisser gauche/droite, glisser vers le bas pour fermer, pincer, double-toucher
(() => {
  const sc = $('#v-scene'); const pts = new Map();
  let debut = null, pince = null, dernierTap = 0, tapT = null, bouge = false;
  sc.addEventListener('pointerdown', ev => {
    if (ev.target.tagName === 'VIDEO') return;
    sc.setPointerCapture?.(ev.pointerId);
    pts.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    bouge = false;
    if (pts.size === 1) debut = { x: ev.clientX, y: ev.clientY, zx: zoom.x, zy: zoom.y, t: Date.now() };
    if (pts.size === 2) {
      const [a, b] = [...pts.values()];
      pince = { d: Math.hypot(a.x - b.x, a.y - b.y), s: zoom.s, mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2, zx: zoom.x, zy: zoom.y };
    }
  });
  sc.addEventListener('pointermove', ev => {
    if (!pts.has(ev.pointerId)) return;
    pts.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    const img = sc.querySelector('img'); if (!img) return;
    if (pts.size === 2 && pince) {
      bouge = true;
      const [a, b] = [...pts.values()];
      const s = Math.max(1, Math.min(8, pince.s * Math.hypot(a.x - b.x, a.y - b.y) / pince.d));
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const r = img.getBoundingClientRect();
      const ox = r.left - zoom.x, oy = r.top - zoom.y; // origine de l'image sans transformation
      // garder le point sous les doigts fixe
      const px = (pince.mx - ox - pince.zx) / pince.s, py = (pince.my - oy - pince.zy) / pince.s;
      zoom.s = s; zoom.x = mx - ox - px * s; zoom.y = my - oy - py * s;
      if (s === 1) { zoom.x = 0; zoom.y = 0; }
      appliquerZoom();
    } else if (pts.size === 1 && debut) {
      const dx = ev.clientX - debut.x, dy = ev.clientY - debut.y;
      if (Math.hypot(dx, dy) > 8) bouge = true;
      if (zoom.s > 1) { zoom.x = debut.zx + dx; zoom.y = debut.zy + dy; appliquerZoom(); }
      else if (bouge) img.style.transform = Math.abs(dx) > Math.abs(dy) ? `translateX(${dx}px)` : (dy > 0 ? `translateY(${dy}px)` : '');
    }
  });
  const fin = ev => {
    if (!pts.has(ev.pointerId)) return;
    pts.delete(ev.pointerId);
    const img = sc.querySelector('img');
    if (pts.size === 1) { const p = [...pts.values()][0]; debut = { x: p.x, y: p.y, zx: zoom.x, zy: zoom.y, t: Date.now() }; pince = null; return; }
    if (pts.size) return;
    pince = null;
    if (!debut) return;
    const dx = ev.clientX - debut.x, dy = ev.clientY - debut.y;
    if (zoom.s === 1 && img) img.style.transform = '';
    if (!bouge) {
      const now = Date.now();
      if (now - dernierTap < 300) { // double toucher
        clearTimeout(tapT); dernierTap = 0;
        if (!img) return;
        if (zoom.s > 1) { zoom.s = 1; zoom.x = 0; zoom.y = 0; }
        else { const r = img.getBoundingClientRect(); const s = 2.5; zoom.s = s; zoom.x = -(ev.clientX - r.left) * (s - 1); zoom.y = -(ev.clientY - r.top) * (s - 1); }
        appliquerZoom();
      } else {
        dernierTap = now;
        tapT = setTimeout(() => $('#visionneuse').classList.toggle('nu'), 280);
      }
    } else if (zoom.s === 1) {
      if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy)) afficher(etat.vue + (dx < 0 ? 1 : -1));
      else if (dy > 110 && Math.abs(dy) > Math.abs(dx)) fermerVisionneuse();
    }
    debut = null;
  };
  sc.addEventListener('pointerup', fin);
  sc.addEventListener('pointercancel', fin);
})();

// Boutons de la visionneuse
$('#v-bas').addEventListener('click', async ev => {
  const a = ev.target.closest('button')?.dataset.a; if (!a) return;
  const e = etat.liste[etat.vue]; if (!e) return;
  if (a === 'copier') return copierImage(e);
  if (a === 'partager') {
    const o = cacheOrig.get(e.id);
    if (!o) return toast('Patiente, le fichier se charge…');
    return partager([new File([o.blob], nomFichier(e), { type: o.blob.type })]);
  }
  if (a === 'ranger') {
    const d = await choisirDossier('Ranger dans…');
    if (d === undefined) return;
    e.dossier = d; await sauverIndex(); majInfo();
    toast('Rangé dans ' + (d ? dossierPar(d).nom : 'Coffre'));
  }
  if (a === 'tags') { if (await editerTags([e])) majInfo(); }
  if (a === 'supprimer') {
    if (!await confirmer('Supprimer définitivement ce fichier du coffre ?', 'Supprimer')) return;
    await supprimer([e.id]);
    etat.liste.splice(etat.vue, 1);
    if (!etat.liste.length) fermerVisionneuse(); else afficher(etat.vue);
  }
});
function nomFichier(e) { return (e.nom && /\.\w+$/.test(e.nom)) ? e.nom : 'image-' + new Date(e.ajoute).toISOString().slice(0, 10) + '.' + extension(e.mime); }
function copierImage(e) {
  if (e.type === 'video') return toast('Les vidéos ne peuvent pas être copiées. Utilise Partager.');
  const o = cacheOrig.get(e.id);
  if (!o || !window.ClipboardItem) return toast('Copie impossible ici. Utilise Partager.');
  const png = (async () => {
    if (o.blob.type === 'image/png') return o.blob;
    const im = new Image(); im.src = o.url; await im.decode();
    const c = document.createElement('canvas'); c.width = im.naturalWidth; c.height = im.naturalHeight;
    c.getContext('2d').drawImage(im, 0, 0);
    return new Promise(r => c.toBlob(r, 'image/png'));
  })();
  navigator.clipboard.write([new ClipboardItem({ 'image/png': png })])
    .then(() => toast('Image copiée'), () => toast('Copie refusée par le téléphone. Utilise Partager.'));
}
async function partager(fichiers) {
  if (navigator.canShare?.({ files: fichiers })) {
    try { await navigator.share({ files: fichiers }); } catch (e) { if (e.name !== 'AbortError') toast('Partage impossible : ' + e.message); }
  } else {
    for (const f of fichiers) { const a = document.createElement('a'); a.href = URL.createObjectURL(f); a.download = f.name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 60000); }
  }
}
async function supprimer(ids) {
  const s = new Set(ids);
  index.elements = index.elements.filter(e => !s.has(e.id));
  await sauverIndex();
  for (const id of ids) {
    await effacer('fichiers', id + ':o'); await effacer('fichiers', id + ':m');
    if (urlsMini.has(id)) { URL.revokeObjectURL(urlsMini.get(id)); urlsMini.delete(id); }
    if (cacheOrig.has(id)) { URL.revokeObjectURL(cacheOrig.get(id).url); cacheOrig.delete(id); }
  }
}

/* ---------- Dialogues ---------- */
function dialogue(d) { return new Promise(res => { d.addEventListener('close', () => res(d.returnValue), { once: true }); d.returnValue = ''; d.showModal(); }); }
async function demanderTexte(titre, valeur = '') {
  $('#dt-titre').textContent = titre; const i = $('#dt-valeur'); i.value = valeur;
  const p = dialogue($('#d-texte')); setTimeout(() => i.focus(), 50);
  return (await p) === 'oui' ? i.value.trim() : null;
}
async function confirmer(texte, bouton = 'OK') {
  $('#dc-texte').textContent = texte; $('#dc-oui').textContent = bouton;
  return (await dialogue($('#d-confirmer'))) === 'oui';
}
async function actions(titre, liste) {
  $('#da-titre').textContent = titre; const l = $('#da-liste'); l.textContent = '';
  liste.forEach((a, i) => { const b = document.createElement('button'); b.value = String(i); b.textContent = a.t; if (a.danger) b.className = 'danger'; l.append(b); });
  const r = await dialogue($('#d-actions'));
  if (r !== '') await liste[+r].f();
}
function choisirDossier(titre, exclure) {
  return new Promise(res => {
    const d = $('#d-dossiers'); $('#dd-titre').textContent = titre;
    const l = $('#dd-liste'); l.textContent = '';
    let choix;
    const ajout = (id, nom, niv) => {
      const b = document.createElement('button'); b.type = 'button'; b.textContent = nom;
      b.style.paddingLeft = (12 + niv * 18) + 'px';
      if (id === etat.dossier) b.classList.add('actuel');
      b.onclick = () => { choix = id; d.close(); };
      l.append(b);
    };
    ajout(null, 'Coffre (non rangés)', 0);
    const parcourir = (p, n) => { for (const x of enfants(p)) { if (exclure?.has(x.id)) continue; ajout(x.id, x.nom, n); parcourir(x.id, n + 1); } };
    parcourir(null, 1);
    $('#dd-nouveau').onclick = async () => {
      d.close();
      const nom = await demanderTexte('Nouveau dossier');
      if (!nom) return res(undefined);
      const nd = creerDossier(nom, null); await sauverIndex();
      res(nd.id);
    };
    d.addEventListener('close', () => { if (choix !== undefined || !$('#d-texte').open) setTimeout(() => { if (!$('#d-texte').open) res(choix); }, 0); }, { once: true });
    d.showModal();
  });
}
async function editerTags(elems) {
  const communs = new Set(elems[0].tags || []);
  for (const e of elems.slice(1)) for (const t of [...communs]) if (!(e.tags || []).includes(t)) communs.delete(t);
  const actifs = new Set(communs);
  const tous = new Set([...index.tags, ...index.elements.flatMap(e => e.tags || [])]);
  const l = $('#dg-liste'), i = $('#dg-valeur'); i.value = '';
  const dessiner = () => {
    l.textContent = '';
    [...tous].sort((a, b) => a.localeCompare(b, 'fr')).forEach(t => {
      const b = document.createElement('button'); b.type = 'button'; b.textContent = t;
      if (actifs.has(t)) b.className = 'actif';
      b.onclick = () => { actifs.has(t) ? actifs.delete(t) : actifs.add(t); dessiner(); };
      l.append(b);
    });
  };
  i.onkeydown = ev => {
    if (ev.key !== 'Enter') return; ev.preventDefault();
    const t = i.value.trim().replace(/\s+/g, ' '); if (!t) return;
    tous.add(t); actifs.add(t); i.value = ''; dessiner();
  };
  dessiner();
  if ((await dialogue($('#d-tags'))) !== 'oui') return false;
  const reste = i.value.trim(); if (reste) { tous.add(reste); actifs.add(reste); }
  for (const e of elems) {
    const garde = (e.tags || []).filter(t => !communs.has(t) || actifs.has(t));
    e.tags = [...new Set([...garde, ...actifs])];
  }
  index.tags = [...new Set([...index.tags, ...actifs])];
  await sauverIndex();
  return true;
}
async function nouveauMdp(titre, obligatoire) {
  $('#dm-titre').textContent = titre; $('#dm-1').value = ''; $('#dm-2').value = ''; $('#dm-erreur').textContent = '';
  $('#dm-annuler').hidden = !!obligatoire;
  const d = $('#d-mdp');
  return new Promise(res => {
    const f = $('#f-mdp');
    f.onsubmit = ev => {
      const btn = ev.submitter?.value;
      if (btn === 'non') return; // fermeture normale
      ev.preventDefault();
      const a = $('#dm-1').value, b = $('#dm-2').value;
      if (a.length < 6) return $('#dm-erreur').textContent = '6 caractères minimum.';
      if (a !== b) return $('#dm-erreur').textContent = 'Les deux mots de passe sont différents.';
      d.close('ok'); res(a);
    };
    d.oncancel = ev => { if (obligatoire) ev.preventDefault(); };
    d.addEventListener('close', () => res(null), { once: true });
    d.returnValue = ''; d.showModal();
  });
}

/* ---------- Démarrage, création, ouverture ---------- */
async function demarrer() {
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
  let meta = null;
  try { meta = await lire('meta', 'coffre'); }
  catch { document.body.innerHTML = '<p style="padding:40px;text-align:center">Le stockage local est indisponible (navigation privée ?).</p>'; return; }
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const installe = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
  if (meta) montrer('e-ouvrir');
  else if (ios && !installe) montrer('e-installer');
  else montrer('e-creer');
}
$('#b-forcer').onclick = () => montrer('e-creer');

$('#f-creer').onsubmit = async ev => {
  ev.preventDefault();
  const a = $('#c-mdp').value, b = $('#c-mdp2').value, err = $('#c-erreur');
  if (a.length < 6) return err.textContent = '6 caractères minimum.';
  if (a !== b) return err.textContent = 'Les deux mots de passe sont différents.';
  err.textContent = '';
  const btn = ev.submitter || $('#f-creer button'); btn.disabled = true; btn.textContent = 'Création…';
  try {
    const code = await creerCoffre(a);
    $('#c-mdp').value = $('#c-mdp2').value = '';
    afficherCode(code, () => entrer());
  } catch (e) { err.textContent = 'Erreur : ' + e.message; }
  finally { btn.disabled = false; btn.textContent = 'Créer le coffre'; }
};
function afficherCode(code, suite) {
  $('#s-code').textContent = code; $('#s-ok').checked = false; $('#s-continuer').disabled = true;
  $('#s-copier').onclick = () => navigator.clipboard.writeText(code).then(() => toast('Code copié. Colle-le en lieu sûr puis vide le presse-papiers.', 4000), () => toast('Copie impossible'));
  $('#s-continuer').onclick = () => { $('#s-code').textContent = ''; suite(); };
  montrer('e-secours');
}
$('#s-ok').onchange = () => { $('#s-continuer').disabled = !$('#s-ok').checked; };

let parSecours = false;
function modeSecours(oui) {
  parSecours = oui;
  const i = $('#o-mdp');
  i.placeholder = oui ? 'Code de secours (XXXX-XXXX-…)' : 'Mot de passe';
  i.type = oui ? 'text' : 'password';
  i.autocapitalize = oui ? 'characters' : 'off';
  $('#b-secours').textContent = oui ? 'Utiliser le mot de passe' : 'Mot de passe oublié ? Utiliser le code de secours';
}
$('#b-secours').onclick = () => { modeSecours(!parSecours); $('#o-erreur').textContent = ''; $('#o-mdp').value = ''; $('#o-mdp').focus(); };
$('#f-ouvrir').onsubmit = async ev => {
  ev.preventDefault();
  const btn = ev.submitter || $('#f-ouvrir button'), err = $('#o-erreur');
  btn.disabled = true; btn.textContent = 'Ouverture…'; err.textContent = '';
  try {
    await ouvrirCoffre($('#o-mdp').value, parSecours);
    $('#o-mdp').value = '';
    entrer();
    if (parSecours) {
      const m = await nouveauMdp('Choisis un nouveau mot de passe', true);
      if (m) { await changerMdp(m); toast('Nouveau mot de passe enregistré'); }
      modeSecours(false);
    }
  } catch (e) { err.textContent = e.message; $('#o-mdp').select(); }
  finally { btn.disabled = false; btn.textContent = 'Ouvrir'; }
};
function entrer() {
  derniereAction = Date.now();
  montrer('e-coffre');
  rendre();
}

/* ---------- Boutons du coffre ---------- */
$('#b-verrou').onclick = () => verrouiller();
$('#b-retour').onclick = () => allerA(dossierPar(etat.dossier)?.parent ?? null);
$('#recherche').oninput = ev => { etat.recherche = ev.target.value; rendre(); };
$('#b-coller').onclick = () => coller();
$('#b-importer').onclick = () => $('#f-importer').click();
$('#f-importer').onchange = async ev => { const f = [...ev.target.files]; ev.target.value = ''; await ajouterFichiers(f); };
$('#b-dossier').onclick = async () => {
  const nom = await demanderTexte(etat.dossier ? 'Nouveau sous-dossier' : 'Nouveau dossier');
  if (!nom) return;
  creerDossier(nom, etat.dossier); await sauverIndex(); rendre();
};
$('#b-menu-dossier').onclick = () => {
  const d = dossierPar(etat.dossier); if (!d) return;
  actions(d.nom, [
    { t: 'Renommer', f: async () => { const n = await demanderTexte('Renommer le dossier', d.nom); if (n) { d.nom = n; await sauverIndex(); rendre(); } } },
    { t: 'Déplacer dans…', f: async () => {
      const p = await choisirDossier('Déplacer « ' + d.nom + ' » dans…', descendants(d.id));
      if (p === undefined) return; d.parent = p; await sauverIndex(); rendre(); } },
    { t: 'Supprimer le dossier (garder son contenu)', danger: true, f: async () => {
      if (!await confirmer(`Supprimer « ${d.nom} » ? Son contenu remonte dans le dossier parent.`, 'Supprimer')) return;
      for (const e of index.elements) if (e.dossier === d.id) e.dossier = d.parent;
      for (const x of index.dossiers) if (x.parent === d.id) x.parent = d.parent;
      index.dossiers = index.dossiers.filter(x => x !== d);
      etat.dossier = d.parent; await sauverIndex(); rendre(); } },
  ]);
};
$('#b-choisir').onclick = () => { etat.selection = new Set(); rendre(); };
$('#s-fin').onclick = () => { etat.selection = null; rendre(); };
$('#s-tout').onclick = () => {
  const tous = etat.liste.every(e => etat.selection.has(e.id));
  etat.selection = tous ? new Set() : new Set(etat.liste.map(e => e.id)); rendre();
};
const choisis = () => index.elements.filter(e => etat.selection?.has(e.id));
$('#s-ranger').onclick = async () => {
  const L = choisis(); if (!L.length) return toast('Rien de choisi');
  const res = await actions(L.length + ' choisi(s)', [
    { t: 'Ranger dans un dossier…', f: async () => {
      const d = await choisirDossier('Ranger dans…'); if (d === undefined) return;
      L.forEach(e => e.dossier = d); etat.selection = null; await sauverIndex(); rendre(); toast('Rangé'); } },
    { t: 'Tags…', f: async () => { if (await editerTags(L)) { etat.selection = null; rendre(); toast('Tags enregistrés'); } } },
  ]);
  return res;
};
$('#s-partager').onclick = async () => {
  const L = choisis(); if (!L.length) return toast('Rien de choisi');
  toast('Préparation…', 0);
  const fichiers = [];
  for (const e of L) {
    const rec = await lire('fichiers', e.id + ':o');
    const buf = await dechiffrer(cle, rec, e.id + ':o');
    fichiers.push(new File([buf], nomFichier(e), { type: e.mime || 'application/octet-stream' }));
  }
  $('#toast').hidden = true;
  // Le partage doit suivre un toucher : on demande une confirmation
  if (await confirmer(`${fichiers.length} fichier(s) prêt(s). Ils sortiront du coffre en clair.`, 'Partager')) partager(fichiers);
};
$('#s-supprimer').onclick = async () => {
  const L = choisis(); if (!L.length) return toast('Rien de choisi');
  if (!await confirmer(`Supprimer définitivement ${L.length} fichier(s) ?`, 'Supprimer')) return;
  await supprimer(L.map(e => e.id)); etat.selection = null; rendre();
};

/* ---------- Glisser-déposer & coller ---------- */
let profondeur = 0;
addEventListener('dragenter', ev => { if (!cle) return; ev.preventDefault(); profondeur++; $('#depot').hidden = false; });
addEventListener('dragleave', () => { if (--profondeur <= 0) { profondeur = 0; $('#depot').hidden = true; } });
addEventListener('dragover', ev => { if (cle) ev.preventDefault(); });
addEventListener('drop', async ev => {
  ev.preventDefault(); profondeur = 0; $('#depot').hidden = true;
  if (!cle) return;
  const f = await fichiersDepuis(ev.dataTransfer);
  if (f.length) ajouterFichiers(f);
});
addEventListener('paste', async ev => {
  if (!cle || ev.target.closest?.('input')) return;
  ev.preventDefault();
  const f = await fichiersDepuis(ev.clipboardData);
  if ($('#d-coller').open) $('#d-coller').close();
  if (f.length) { const n = await ajouterFichiers(f); if (n && reglages.viderPP) navigator.clipboard?.writeText(' ').catch(() => {}); }
  else toast('Pas d’image dans le presse-papiers.');
});
$('#zone-coller').addEventListener('input', ev => { ev.target.textContent = ''; });

/* ---------- Réglages ---------- */
$('#b-reglages').onclick = async () => {
  $('#r-verrou').value = reglages.verrou; $('#r-inactivite').value = reglages.inactivite; $('#r-vider').checked = reglages.viderPP;
  const total = index.elements.reduce((s, e) => s + e.taille, 0);
  let txt = `${index.elements.length} fichier(s) · ${taille(total)}`;
  try { const es = await navigator.storage.estimate(); if (es.quota) txt += ` · espace libre pour le coffre ≈ ${taille(es.quota - es.usage)}`; } catch {}
  $('#r-espace').textContent = txt + ` · version ${VERSION}`;
  $('#d-reglages').showModal();
};
$('#r-verrou').onchange = ev => { reglages.verrou = +ev.target.value; sauverReglages(); };
$('#r-inactivite').onchange = ev => { reglages.inactivite = +ev.target.value; sauverReglages(); };
$('#r-vider').onchange = ev => { reglages.viderPP = ev.target.checked; sauverReglages(); };
$('#r-mdp').onclick = async () => {
  $('#d-reglages').close();
  const m = await nouveauMdp('Nouveau mot de passe');
  if (m) { await changerMdp(m); toast('Mot de passe changé'); }
};
$('#r-code').onclick = async () => {
  $('#d-reglages').close();
  if (!await confirmer('Créer un nouveau code de secours ? L’ancien ne marchera plus.', 'Créer')) return;
  const code = await changerCode();
  afficherCode(code, () => entrer());
};
$('#r-export').onclick = async () => { $('#d-reglages').close(); await exporter(); };
$('#r-effacer').onclick = async () => {
  $('#d-reglages').close();
  if (!await confirmer('Supprimer TOUT le coffre de ce téléphone ? Rien ne pourra être récupéré sans sauvegarde.', 'Continuer')) return;
  const t = await demanderTexte('Écris EFFACER pour confirmer');
  if (t !== 'EFFACER') return toast('Annulé');
  verrouiller(); await toutVider(); montrer('e-creer');
};

/* ---------- Sauvegarde chiffrée ---------- */
const metaVersJSON = m => ({ v: m.v, iter: m.iter, sm: b64(m.sm), ss: b64(m.ss),
  cm: { iv: b64(m.cm.iv), data: b64(m.cm.data) }, cs: { iv: b64(m.cs.iv), data: b64(m.cs.data) } });
const metaDepuisJSON = m => ({ v: m.v, iter: m.iter, sm: deb64(m.sm), ss: deb64(m.ss),
  cm: { iv: deb64(m.cm.iv), data: deb64(m.cm.data).buffer }, cs: { iv: deb64(m.cs.iv), data: deb64(m.cs.data).buffer } });
async function exporter() {
  toast('Préparation de la sauvegarde…', 0);
  await fileSauve;
  const meta = await lire('meta', 'coffre'), ri = await lire('meta', 'index');
  const cles = await toutesCles('fichiers');
  const fichiers = [], parts = [];
  for (const k of cles) {
    const r = await lire('fichiers', k);
    const b = r.data instanceof Blob ? r.data : new Blob([r.data]);
    fichiers.push({ k, iv: b64(r.iv), n: b.size }); parts.push(b);
  }
  const tete = enc.encode(JSON.stringify({ format: 'coffre', v: 1, cree: Date.now(), meta: metaVersJSON(meta),
    index: { iv: b64(ri.iv), data: b64(ri.data) }, fichiers }));
  const lg = new Uint8Array(4); new DataView(lg.buffer).setUint32(0, tete.length, true);
  const blob = new Blob([enc.encode('COFFRE01'), lg, tete, ...parts], { type: 'application/octet-stream' });
  $('#toast').hidden = true;
  const nom = 'sauvegarde-' + new Date().toISOString().slice(0, 10) + '.coffre';
  if (!await confirmer(`Sauvegarde prête (${taille(blob.size)}). Elle reste chiffrée : pour la restaurer il faudra le mot de passe ou le code de secours actuels. Range-la dans Fichiers (iCloud Drive ou sur le téléphone).`, 'Enregistrer')) return;
  partager([new File([blob], nom, { type: 'application/octet-stream' })]);
}
$('#b-restaurer').onclick = () => $('#f-restaurer').click();
$('#f-restaurer').onchange = async ev => {
  const f = ev.target.files[0]; ev.target.value = ''; if (!f) return;
  try {
    const magic = dec.decode(await f.slice(0, 8).arrayBuffer());
    if (magic !== 'COFFRE01') throw new Error('ce fichier n’est pas une sauvegarde du coffre');
    const n = new DataView(await f.slice(8, 12).arrayBuffer()).getUint32(0, true);
    const t = JSON.parse(dec.decode(await f.slice(12, 12 + n).arrayBuffer()));
    let pos = 12 + n;
    for (let i = 0; i < t.fichiers.length; i++) {
      const x = t.fichiers[i];
      toast(`Restauration ${i + 1} / ${t.fichiers.length}…`, 0);
      const buf = await f.slice(pos, pos + x.n).arrayBuffer(); pos += x.n;
      await ecrire('fichiers', x.k, { iv: deb64(x.iv), data: new Blob([buf]) });
    }
    await ecrire('meta', 'index', { iv: deb64(t.index.iv), data: deb64(t.index.data).buffer });
    await ecrire('meta', 'coffre', metaDepuisJSON(t.meta));
    navigator.storage?.persist?.().catch(() => {});
    toast('Sauvegarde restaurée. Ouvre-la avec son mot de passe.', 4000);
    montrer('e-ouvrir');
  } catch (e) { toast('Restauration impossible : ' + e.message, 6000); }
};

/* ---------- Verrouillage automatique & masquage ---------- */
let derniereAction = Date.now(), quitte = 0;
['pointerdown', 'keydown', 'scroll'].forEach(t => addEventListener(t, () => { derniereAction = Date.now(); }, { passive: true, capture: true }));
function cacher() { document.body.classList.add('masque'); if (!quitte) quitte = Date.now(); $('#v-scene video')?.pause(); }
function revenir() {
  if (!quitte) return;
  const absent = Date.now() - quitte; quitte = 0;
  if (cle && absent >= reglages.verrou * 1000 && !ajoutEnCours) verrouiller();
  document.body.classList.remove('masque');
  derniereAction = Date.now();
}
document.addEventListener('visibilitychange', () => document.hidden ? cacher() : revenir());
addEventListener('pagehide', cacher);
addEventListener('pageshow', () => { if (!document.hidden) revenir(); });
setInterval(() => {
  if (!cle || !reglages.inactivite || ajoutEnCours) return;
  const v = $('#v-scene video'); if (v && !v.paused) derniereAction = Date.now();
  if (Date.now() - derniereAction > reglages.inactivite * 1000) verrouiller();
}, 10000);

demarrer();
