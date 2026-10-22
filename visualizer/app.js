// Bootlegger Interactive Steganography Visualizer
// Data model matching the 23-block TAR test archive

const ARCHIVE_MODEL = [
  // Block 0: Header for src/main.rs
  { id: 0, type: "header", file: "src/main.rs", size: 512, slack: 0, hex: "73 72 63 2f 6d 61 69 6e 2e 72 73 00 00 00 00 00  src/main.rs.....", entropy: 3.8 },
  // Blocks 1-4: Pure Data for src/main.rs
  { id: 1, type: "data", file: "src/main.rs", size: 512, slack: 0, hex: "66 6e 20 6d 61 69 6e 28 29 20 7b 0a 20 20 70 72  fn main() {.  pr", entropy: 5.2 },
  { id: 2, type: "data", file: "src/main.rs", size: 512, slack: 0, hex: "69 6e 74 6c 6e 21 28 22 4f 72 64 69 6e 61 72 79  intln!(\"Ordinary", entropy: 5.1 },
  { id: 3, type: "data", file: "src/main.rs", size: 512, slack: 0, hex: "20 75 74 69 6c 69 74 79 20 70 72 6f 67 72 61 6d   utility program", entropy: 4.9 },
  { id: 4, type: "data", file: "src/main.rs", size: 512, slack: 0, hex: "20 76 31 2e 30 22 29 3b 0a 7d 0a 0a 2f 2f 20 63   v1.0\");.}..// c", entropy: 5.3 },
  // Block 5: Last block of src/main.rs (232 bytes data + 280 bytes slack!)
  { id: 5, type: "slack", file: "src/main.rs", size: 232, slack: 280, hasShards: true, hex: "6c 65 61 6e 20 63 6f 64 65 [SLACK: 0x8f 0x2b 0x9a]  lean code..+...", entropy: 5.8 },

  // Block 6: Header for docs/guide.md
  { id: 6, type: "header", file: "docs/guide.md", size: 512, slack: 0, hex: "64 6f 63 73 2f 67 75 69 64 65 2e 6d 64 00 00 00  docs/guide.md...", entropy: 3.9 },
  // Blocks 7-11: Data for docs/guide.md
  { id: 7, type: "data", file: "docs/guide.md", size: 512, slack: 0, hex: "23 20 55 73 65 72 20 44 6f 63 75 6d 65 6e 74 61  # User Documenta", entropy: 4.8 },
  { id: 8, type: "data", file: "docs/guide.md", size: 512, slack: 0, hex: "74 69 6f 6e 0a 54 68 69 73 20 73 6f 66 74 77 61  tion.This softwa", entropy: 5.0 },
  { id: 9, type: "data", file: "docs/guide.md", size: 512, slack: 0, hex: "72 65 20 70 65 72 66 6f 72 6d 73 20 72 65 67 75  re performs regu", entropy: 5.2 },
  { id: 10, type: "data", file: "docs/guide.md", size: 512, slack: 0, hex: "6c 61 72 20 6c 6f 67 67 69 6e 67 20 61 6e 64 20  lar logging and ", entropy: 4.7 },
  { id: 11, type: "data", file: "docs/guide.md", size: 512, slack: 0, hex: "74 65 6c 65 6d 65 74 72 79 2e 0a 23 20 41 72 63  telemetry..# Arc", entropy: 5.1 },
  // Block 12: Last block of docs/guide.md (65 bytes data + 447 bytes slack!)
  { id: 12, type: "slack", file: "docs/guide.md", size: 65, slack: 447, hasShards: true, hex: "68 69 74 65 63 74 75 72 65 [SLACK: 0x4a 0x7e 0x01]  hitecture.~....", entropy: 5.9 },

  // Block 13: Header for docs/faq.txt
  { id: 13, type: "header", file: "docs/faq.txt", size: 512, slack: 0, hex: "64 6f 63 73 2f 66 61 71 2e 74 78 74 00 00 00 00  docs/faq.txt....", entropy: 3.7 },
  // Blocks 14-15: Data for docs/faq.txt
  { id: 14, type: "data", file: "docs/faq.txt", size: 512, slack: 0, hex: "51 3a 20 48 6f 77 20 64 6f 65 73 20 74 68 69 73  Q: How does this", entropy: 4.9 },
  { id: 15, type: "data", file: "docs/faq.txt", size: 512, slack: 0, hex: "20 70 72 6f 67 72 61 6d 20 77 6f 72 6b 3f 0a 41   program work?.A", entropy: 5.0 },
  // Block 16: Last block of docs/faq.txt (336 bytes data + 176 bytes slack!)
  { id: 16, type: "slack", file: "docs/faq.txt", size: 336, slack: 176, hasShards: true, hex: "3a 20 49 74 20 70 72 6f 63 [SLACK: 0x11 0x55 0xfe]  : It proc..U...", entropy: 5.7 },

  // Block 17: Header for Cargo.toml
  { id: 17, type: "header", file: "Cargo.toml", size: 512, slack: 0, hex: "43 61 72 67 6f 2e 74 6f 6d 6c 00 00 00 00 00 00  Cargo.toml......", entropy: 3.6 },
  // Block 18: Cargo.toml data (64 bytes data + 448 bytes slack!)
  { id: 18, type: "slack", file: "Cargo.toml", size: 64, slack: 448, hasShards: true, hex: "5b 70 61 63 6b 61 67 65 5d [SLACK: 0xcc 0x99 0x88]  [package].......", entropy: 6.0 },

  // Block 19: Header for license.txt
  { id: 19, type: "header", file: "license.txt", size: 512, slack: 0, hex: "6c 69 63 65 6e 73 65 2e 74 78 74 00 00 00 00 00  license.txt.....", entropy: 3.8 },
  // Block 20: license.txt data (405 bytes data + 107 bytes slack!)
  { id: 20, type: "slack", file: "license.txt", size: 405, slack: 107, hasShards: true, hex: "4d 6f 7a 69 6c 6c 61 20 50 [SLACK: 0x33 0xaa 0x77]  Mozilla P..3.w..", entropy: 5.6 },

  // Blocks 21-22: End-of-Archive (Zero blocks)
  { id: 21, type: "eoa", file: "End-of-Archive (EOA)", size: 0, slack: 512, hex: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................", entropy: 0.0 },
  { id: 22, type: "eoa", file: "End-of-Archive (EOA)", size: 0, slack: 512, hex: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................", entropy: 0.0 }
];

let state = {
  isTampered: false,
  tamperedBlockId: null,
  activeTier: null // 'primary' | 'duress' | null
};

// DOM Elements
const blockGrid = document.getElementById("blockGrid");
const entropyChart = document.getElementById("entropyChart");
const passphraseInput = document.getElementById("passphraseInput");
const btnDecrypt = document.getElementById("btnDecrypt");
const resultBanner = document.getElementById("resultBanner");
const resultStatus = document.getElementById("resultStatus");
const resultDetails = document.getElementById("resultDetails");
const btnTamper = document.getElementById("btnTamper");
const btnResetTamper = document.getElementById("btnResetTamper");
const tripwireBadge = document.getElementById("tripwireBadge");
const tripwireIndicator = document.getElementById("tripwireIndicator");
const inspTitle = document.getElementById("inspTitle");
const inspMeta = document.getElementById("inspMeta");
const inspHex = document.getElementById("inspHex");

// Initialize Render
function renderGrid() {
  blockGrid.innerHTML = "";
  ARCHIVE_MODEL.forEach((block) => {
    const el = document.createElement("div");
    el.className = `block-item block-${block.type}`;
    el.dataset.id = block.id;

    // Tamper state
    if (state.isTampered && state.tamperedBlockId === block.id) {
      el.classList.add("block-tampered");
    }

    // Active shards
    if (block.hasShards) {
      if (state.activeTier === "primary") {
        el.classList.add("block-primary-shard");
      } else if (state.activeTier === "duress") {
        el.classList.add("block-duress-shard");
      } else {
        el.classList.add("block-slack-pure");
      }
    }

    let typeTag = block.type.toUpperCase();
    if (block.hasShards && state.activeTier === "primary") typeTag = "PRNG-SHARD (A)";
    else if (block.hasShards && state.activeTier === "duress") typeTag = "DURESS-SHARD (B)";
    else if (block.hasShards) typeTag = `SLACK (${block.slack}B)`;

    el.innerHTML = `
      <div class="block-id">#${block.id}</div>
      <div class="block-tag">${typeTag}</div>
    `;

    el.addEventListener("mouseenter", () => inspectBlock(block));
    el.addEventListener("click", () => inspectBlock(block));

    blockGrid.appendChild(el);
  });
}

function renderEntropyChart() {
  entropyChart.innerHTML = "";
  ARCHIVE_MODEL.forEach((block) => {
    const bar = document.createElement("div");
    bar.className = "entropy-bar";
    const heightPercent = Math.max(6, (block.entropy / 8.0) * 100);
    bar.style.height = `${heightPercent}%`;
    bar.title = `Block #${block.id} (${block.file}): Entropy ${block.entropy.toFixed(2)}`;
    entropyChart.appendChild(bar);
  });
}

function inspectBlock(block) {
  inspTitle.textContent = `Block #${block.id} — ${block.file}`;
  const offsetHex = `0x${(block.id * 512).toString(16).padStart(4, "0").toUpperCase()}`;
  let typeDesc = "Regular USTAR 512B Block";
  if (block.type === "header") typeDesc = "POSIX USTAR Header (Metadata, checksum, octal size)";
  if (block.type === "data") typeDesc = "Legitimate Cover Payload (Visible plain data)";
  if (block.type === "slack") typeDesc = `Data (${block.size}B) + Natural Intra-Block Slack (${block.slack}B)`;
  if (block.type === "eoa") typeDesc = "End-of-Archive (Zero delimiter blocks)";

  inspMeta.textContent = `Offset: ${offsetHex} | Length: 512B | Type: ${typeDesc}`;
  inspHex.textContent = block.hex;
}

// Decryption Pipeline Simulation
function performDecryption() {
  const pass = passphraseInput.value.trim();

  // 1. Tripwire check
  if (state.isTampered) {
    state.activeTier = null;
    resultBanner.className = "result-banner error";
    resultStatus.textContent = "🚨 TRIPWIRE ALARM: CARRIER TAMPER DETECTED!";
    resultStatus.style.color = "#ef4444";
    resultDetails.innerHTML = `
      Poly1305 MAC verification failed on AAD.<br>
      A bit in block #${state.tamperedBlockId} was altered by an investigator.<br>
      <strong>Self-Destruct Engaged:</strong> Payload decryption irrevocably aborted.
    `;
    renderGrid();
    return;
  }

  // 2. Master Password
  if (pass === "MasterKey2027!") {
    state.activeTier = "primary";
    resultBanner.className = "result-banner success-master";
    resultStatus.textContent = "🔓 Master Vault Unlocked (Primary Secret)";
    resultStatus.style.color = "#a855f7";
    resultDetails.innerHTML = `
      Recovered file: <strong>'real_master_key.pem'</strong> (256-bit Private Key)<br>
      Assembled 4 micro-shards across sub-slots A via ChaCha20 PRNG schedule.<br>
      Tripwire Verified: Carrier 100% intact (5 files checked, 0 byte shift).
    `;
    renderGrid();
    return;
  }

  // 3. Duress Password (Coercion defense)
  if (pass === "CoercedDuressPass!") {
    state.activeTier = "duress";
    resultBanner.className = "result-banner success-duress";
    resultStatus.textContent = "🔓 Duress Vault Unlocked (Plausible Decoy Secret)";
    resultStatus.style.color = "#10b981";
    resultDetails.innerHTML = `
      Recovered file: <strong>'innocent_draft.txt'</strong> (Decoy Meeting Minutes)<br>
      Assembled 4 micro-shards across sub-slots B via Duress PRNG schedule.<br>
      <strong>Plausible Deniability:</strong> Investigator sees 100% valid decoy secret.<br>
      Zero mathematical or statistical trace that Primary Secret exists!
    `;
    renderGrid();
    return;
  }

  // 4. Invalid Password
  state.activeTier = null;
  resultBanner.className = "result-banner error";
  resultStatus.textContent = "❌ Authentication Failed";
  resultStatus.style.color = "#f87171";
  resultDetails.textContent = "Invalid passphrase or corrupted salt. Poly1305 tag mismatch on all candidate tiers.";
  renderGrid();
}

// Event Listeners
btnDecrypt.addEventListener("click", performDecryption);

document.querySelectorAll(".btn-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    passphraseInput.value = chip.dataset.pass;
    performDecryption();
  });
});

btnTamper.addEventListener("click", () => {
  state.isTampered = true;
  state.tamperedBlockId = 2; // Tamper with src/main.rs data block
  tripwireBadge.className = "badge badge-tripwire tripped";
  tripwireBadge.textContent = "🚨 Tripwire: TRIPPED!";
  tripwireIndicator.className = "tripwire-indicator tripped";
  tripwireIndicator.textContent = "TAMPER DETECTED (BLOCK #2)";
  performDecryption();
});

btnResetTamper.addEventListener("click", () => {
  state.isTampered = false;
  state.tamperedBlockId = null;
  tripwireBadge.className = "badge badge-tripwire";
  tripwireBadge.textContent = "🛡️ Tripwire: ARMED";
  tripwireIndicator.className = "tripwire-indicator clean";
  tripwireIndicator.textContent = "INTEGRITY 100% INTACT";
  performDecryption();
});

// Initial boot
renderGrid();
renderEntropyChart();
inspectBlock(ARCHIVE_MODEL[0]);
