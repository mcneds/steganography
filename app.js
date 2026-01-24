// Stego Tool (static)
// - 2 LSBs into RGB bytes (alpha untouched)
// - per-image header: MAGIC + version + flags + total_len + chunk_index + chunk_count + chunk_len
// - optional encryption: AES-GCM with a base64 key (32 bytes). Encrypted payload = "ENC1" + IV(12) + ciphertext

const MAGIC = [0x53,0x54,0x47,0x31]; // "STG1"
const VERSION = 1;
const FLAG_ENCRYPTED = 0x01;

// header layout (big-endian)
// magic(4) version(1) flags(1) total_len(u64) chunk_index(u32) chunk_count(u32) chunk_len(u32)
const HEADER_LEN = 4 + 1 + 1 + 8 + 4 + 4 + 4;

const $ = (id) => document.getElementById(id);

const logEl = $("log");
function log(msg){
  const ts = new Date().toLocaleTimeString();
  logEl.textContent += `[${ts}] ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function clearLog(){ logEl.textContent = ""; }

// -------------------------
// Base64 helpers (URL-safe tolerant)
// -------------------------
function bytesToBase64(bytes){
  let bin = "";
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(b64){
  const clean = b64.trim()
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s+/g, "");
  const pad = clean.length % 4 === 0 ? clean : clean + "=".repeat(4 - (clean.length % 4));
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...parts){
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts){
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// -------------------------
// Header pack/unpack
// -------------------------
function packHeader(flags, totalLen, chunkIndex, chunkCount, chunkLen){
  const buf = new ArrayBuffer(HEADER_LEN);
  const dv = new DataView(buf);
  // magic
  for (let i=0;i<4;i++) dv.setUint8(i, MAGIC[i]);
  dv.setUint8(4, VERSION);
  dv.setUint8(5, flags & 0xFF);

  // totalLen as BigInt
  dv.setBigUint64(6, BigInt(totalLen), false);
  dv.setUint32(14, chunkIndex >>> 0, false);
  dv.setUint32(18, chunkCount >>> 0, false);
  dv.setUint32(22, chunkLen >>> 0, false);

  return new Uint8Array(buf);
}

function unpackHeader(headerBytes){
  if (!(headerBytes instanceof Uint8Array) || headerBytes.length < HEADER_LEN){
    throw new Error("Header too short.");
  }
  for (let i=0;i<4;i++){
    if (headerBytes[i] !== MAGIC[i]) throw new Error("Not a valid stego image (missing MAGIC).");
  }
  const dv = new DataView(headerBytes.buffer, headerBytes.byteOffset, HEADER_LEN);
  const ver = dv.getUint8(4);
  if (ver !== VERSION) throw new Error(`Unsupported stego version: ${ver}`);
  const flags = dv.getUint8(5);
  const totalLen = Number(dv.getBigUint64(6, false));
  const chunkIndex = dv.getUint32(14, false);
  const chunkCount = dv.getUint32(18, false);
  const chunkLen = dv.getUint32(22, false);
  return { flags, totalLen, chunkIndex, chunkCount, chunkLen };
}

// -------------------------
// WebCrypto AES-GCM (optional)
// -------------------------
async function cryptoGenerateKeyB64(){
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(raw);
}

async function aesGcmEncrypt(plainBytes, keyB64){
  const keyRaw = base64ToBytes(keyB64);
  if (keyRaw.length !== 32) throw new Error("Key must decode to 32 bytes (base64). Use Generate Key.");
  const key = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, plainBytes));
  // Format: "ENC1" + iv(12) + ciphertext
  return concatBytes(new TextEncoder().encode("ENC1"), iv, ct);
}

async function aesGcmDecrypt(encBytes, keyB64){
  const keyRaw = base64ToBytes(keyB64);
  if (keyRaw.length !== 32) throw new Error("Key must decode to 32 bytes (base64).");
  const key = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["decrypt"]);

  const tag = new TextDecoder().decode(encBytes.slice(0,4));
  if (tag !== "ENC1") throw new Error("Encrypted payload missing ENC1 marker (wrong data?).");
  const iv = encBytes.slice(4, 16);
  const ct = encBytes.slice(16);

  try{
    return new Uint8Array(await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct));
  }catch(e){
    throw new Error("Decryption failed (wrong key or corrupted data).");
  }
}

// -------------------------
// Image IO helpers
// -------------------------
async function fileToBytes(file){
  const ab = await file.arrayBuffer();
  return new Uint8Array(ab);
}

async function loadImageDataFromFile(file){
  const bmp = await createImageBitmap(file);
  const canvas = document.createElement("canvas");
  canvas.width = bmp.width;
  canvas.height = bmp.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height); // RGBA
  return { canvas, ctx, img };
}

function capacityBytesFromImageData(imgData){
  const w = imgData.width;
  const h = imgData.height;
  const usable = w * h * 3;        // RGB bytes
  return Math.floor(usable / 4);   // 4 carrier bytes per payload byte (2 bits each)
}

function* iterRgbIndices(rgbaLength){
  // RGBA layout => alpha indices are i%4==3. We skip alpha.
  for (let i=0;i<rgbaLength;i++){
    if ((i % 4) !== 3) yield i;
  }
}

function* iter2bitGroups(payloadBytes){
  for (let i=0;i<payloadBytes.length;i++){
    const b = payloadBytes[i];
    yield (b >> 6) & 3;
    yield (b >> 4) & 3;
    yield (b >> 2) & 3;
    yield b & 3;
  }
}

function embedPayloadIntoImageData(imgData, payloadBytes){
  const cap = capacityBytesFromImageData(imgData);
  if (payloadBytes.length > cap){
    throw new Error(`Carrier too small: can hold ${cap} bytes, payload is ${payloadBytes.length} bytes.`);
  }

  const data = imgData.data; // Uint8ClampedArray
  const bits = iter2bitGroups(payloadBytes);
  let usedGroups = 0;

  for (const idx of iterRgbIndices(data.length)){
    const next = bits.next();
    if (next.done) break;
    const two = next.value;
    data[idx] = (data[idx] & 0xFC) | two;
    usedGroups++;
  }

  // Ensure all groups consumed
  if (!bits.next().done){
    throw new Error("Ran out of carrier bytes while embedding.");
  }

  return usedGroups; // 2-bit groups used
}

function extractBytesFromImageData(imgData, byteCount){
  const data = imgData.data;
  const out = new Uint8Array(byteCount);

  let outIndex = 0;
  let acc = 0;
  let bits = 0;

  for (const idx of iterRgbIndices(data.length)){
    const two = data[idx] & 3;
    acc = (acc << 2) | two;
    bits += 2;

    if (bits === 8){
      out[outIndex++] = acc & 0xFF;
      if (outIndex >= byteCount) break;
      acc = 0;
      bits = 0;
    }
  }

  if (outIndex < byteCount){
    throw new Error(`Not enough embedded data: wanted ${byteCount} bytes, got ${outIndex}.`);
  }

  return out;
}

// -------------------------
// Embed workflow
// -------------------------
async function doEmbed(){
  $("embed-downloads").innerHTML = "";
  $("embed-summary").textContent = "";

  const payloadFile = $("file-payload").files[0] || null;
  const carriers = Array.from($("files-carriers").files || []);
  const key = $("enc-key").value.trim();
  const prefix = ($("out-prefix").value || "encoded_").trim();

  if (!payloadFile) throw new Error("Pick a file to embed.");
  if (carriers.length === 0) throw new Error("Pick at least one carrier image.");

  log(`Embed: reading payload "${payloadFile.name}" (${payloadFile.size} bytes)`);
  let payload = await fileToBytes(payloadFile);
  let flags = 0;

  if (key){
    log("Encryption enabled (AES-GCM).");
    payload = await aesGcmEncrypt(payload, key);
    flags |= FLAG_ENCRYPTED;
    log(`Encrypted payload size: ${payload.length} bytes`);
  }else{
    log("Encryption: off.");
  }

  const totalLen = payload.length;

  // Plan chunking based on each carrier capacity minus header
  const plans = [];
  let offset = 0;

  for (const imgFile of carriers){
    const { img } = await loadImageDataFromFile(imgFile);
    const cap = capacityBytesFromImageData(img);
    const room = cap - HEADER_LEN;
    if (room <= 0) throw new Error(`Carrier "${imgFile.name}" is too small to store the header.`);
    if (offset >= totalLen) break;

    const chunkLen = Math.min(room, totalLen - offset);
    plans.push({ imgFile, chunkLen });
    offset += chunkLen;
  }

  if (offset < totalLen){
    throw new Error("Not enough capacity across the selected images. Add more/larger carrier images.");
  }

  const chunkCount = plans.length;
  log(`Chunk plan: ${chunkCount} image(s), total embedded bytes: ${totalLen}.`);

  // Actually embed and make downloadable PNGs
  const downloads = $("embed-downloads");
  let embeddedBytesTotal = 0;

  for (let i=0;i<plans.length;i++){
    const imgFile = plans[i].imgFile;

    const { canvas, ctx, img } = await loadImageDataFromFile(imgFile);
    const cap = capacityBytesFromImageData(img);
    const room = cap - HEADER_LEN;

    const chunk = payload.slice(embeddedBytesTotal, embeddedBytesTotal + room);
    const header = packHeader(flags, totalLen, i, chunkCount, chunk.length);
    const packet = concatBytes(header, chunk);

    log(`Embedding chunk ${i+1}/${chunkCount} into "${imgFile.name}" (packet ${packet.length} bytes, cap ${cap} bytes)`);

    embedPayloadIntoImageData(img, packet);
    ctx.putImageData(img, 0, 0);

    const blob = await new Promise((res) => canvas.toBlob(res, "image/png"));
    const url = URL.createObjectURL(blob);

    const safeBase = imgFile.name.replace(/\.[^.]+$/, "");
    const outName = `${prefix}${String(i).padStart(3,"0")}_${safeBase}.png`;

    const a = document.createElement("a");
    a.href = url;
    a.download = outName;
    a.textContent = outName;

    downloads.appendChild(a);

    embeddedBytesTotal += chunk.length;
  }

  $("embed-summary").textContent = `Done. Created ${chunkCount} PNG(s).`;
  log("Embed: done.");
}

// -------------------------
// Extract workflow
// -------------------------
async function doExtract(){
  $("extract-download").innerHTML = "";
  $("extract-summary").textContent = "";

  const encoded = Array.from($("files-encoded").files || []);
  const key = $("dec-key").value.trim();
  const outName = ($("out-filename").value || "extracted.bin").trim();

  if (encoded.length === 0) throw new Error("Pick at least one encoded image.");

  // Sort by name helps when you select a bunch
  encoded.sort((a,b) => a.name.localeCompare(b.name));

  const chunks = new Map(); // chunkIndex -> Uint8Array
  let expected = null; // {flags,totalLen,chunkCount}

  for (const imgFile of encoded){
    log(`Extract: reading "${imgFile.name}"`);
    const { img } = await loadImageDataFromFile(imgFile);

    const headerBytes = extractBytesFromImageData(img, HEADER_LEN);
    const h = unpackHeader(headerBytes);

    const chunkBytes = extractBytesFromImageData(img, HEADER_LEN + h.chunkLen).slice(HEADER_LEN);

    if (!expected){
      expected = { flags: h.flags, totalLen: h.totalLen, chunkCount: h.chunkCount };
      log(`Header: flags=${h.flags} totalLen=${h.totalLen} chunkCount=${h.chunkCount}`);
    }else{
      if (h.flags !== expected.flags || h.totalLen !== expected.totalLen || h.chunkCount !== expected.chunkCount){
        throw new Error("Encoded images do not match the same embedded file (header mismatch).");
      }
    }

    if (chunks.has(h.chunkIndex)){
      throw new Error(`Duplicate chunk index ${h.chunkIndex} detected.`);
    }
    chunks.set(h.chunkIndex, chunkBytes);
    log(`Got chunk ${h.chunkIndex + 1}/${h.chunkCount} (${chunkBytes.length} bytes)`);
  }

  if (!expected) throw new Error("No valid data found.");

  // Ensure all chunks present
  for (let i=0;i<expected.chunkCount;i++){
    if (!chunks.has(i)){
      throw new Error(`Missing chunk ${i}. Provide all encoded images.`);
    }
  }

  // Assemble
  let assembledParts = [];
  for (let i=0;i<expected.chunkCount;i++){
    assembledParts.push(chunks.get(i));
  }
  let assembled = concatBytes(...assembledParts).slice(0, expected.totalLen);
  log(`Assembled embedded payload: ${assembled.length} bytes`);

  // Decrypt if needed
  if ((expected.flags & FLAG_ENCRYPTED) !== 0){
    if (!key) throw new Error("This payload is encrypted. Provide the key.");
    log("Decrypting (AES-GCM)...");
    assembled = await aesGcmDecrypt(assembled, key);
    log(`Decrypted output: ${assembled.length} bytes`);
  }

  // Download
  const blob = new Blob([assembled], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = outName;
  a.textContent = `Download ${outName} (${assembled.length} bytes)`;

  $("extract-download").appendChild(a);
  $("extract-summary").textContent = "Done.";
  log("Extract: done.");
}

// -------------------------
// Tabs + wiring
// -------------------------
function setTab(which){
  const embedBtn = $("tab-embed");
  const extractBtn = $("tab-extract");
  const embedPanel = $("panel-embed");
  const extractPanel = $("panel-extract");

  if (which === "embed"){
    embedBtn.classList.add("tab-active");
    extractBtn.classList.remove("tab-active");
    embedPanel.classList.add("panel-active");
    extractPanel.classList.remove("panel-active");
  }else{
    extractBtn.classList.add("tab-active");
    embedBtn.classList.remove("tab-active");
    extractPanel.classList.add("panel-active");
    embedPanel.classList.remove("panel-active");
  }
}

function wire(){
  $("tab-embed").addEventListener("click", () => setTab("embed"));
  $("tab-extract").addEventListener("click", () => setTab("extract"));
  $("btn-clear-log").addEventListener("click", clearLog);

  $("btn-gen-key").addEventListener("click", async () => {
    const key = await cryptoGenerateKeyB64();
    $("enc-key").value = key;
    $("dec-key").value = key;
    log("Generated encryption key (base64, 32 bytes).");
  });

  $("btn-embed").addEventListener("click", async () => {
    try{
      log("---- EMBED START ----");
      await doEmbed();
      log("---- EMBED END ----");
    }catch(e){
      log(`ERROR: ${e.message || e}`);
      $("embed-summary").textContent = `Error: ${e.message || e}`;
      alert(e.message || String(e));
    }
  });

  $("btn-extract").addEventListener("click", async () => {
    try{
      log("---- EXTRACT START ----");
      await doExtract();
      log("---- EXTRACT END ----");
    }catch(e){
      log(`ERROR: ${e.message || e}`);
      $("extract-summary").textContent = `Error: ${e.message || e}`;
      alert(e.message || String(e));
    }
  });

  log("Ready.");
}

wire();
