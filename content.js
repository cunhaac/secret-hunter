// --------------------
// CRITICAL patterns
// --------------------
const CRITICAL_PATTERNS = [

  // Amazon AWS
  /AKIA[0-9A-Z]{16}/,                                   // Access Key ID
  /ASIA[0-9A-Z]{16}/,                                   // Temporary STS key
  /A3T[A-Z0-9]{16}/,                                    // AWS Device Auth
  /AKTP[0-9A-Z]{16}/,                                   // AWS Finance Key

  // AWS Secret Key
  /(?:aws_)?secret(?:_access)?_key[^A-Za-z0-9]*([A-Za-z0-9\/+=]{40})/i,

  // Google Cloud
  // /AIza[0-9A-Za-z\-_]{35}/,                          // GCP API key MANY LEGITIMATE EXPOSED KEYS
  /ya29\.[0-9A-Za-z\-_]+/,                              // OAuth Google Access Token
  /[0-9a-f]{64}_apps\.googleusercontent\.com/,          // OAuth Client Secret

  // Firebase
  /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/,            // FCM Server Key
  
  // GitHub
  /gh[pousr]_[A-Za-z0-9]{36}/,
  
  // GitLab
  /glpat-[A-Za-z0-9\-]{20,50}/,                         // Personal Access Token
  /glptt-[A-Za-z0-9\-]{20,50}/,                         // Trigger Token

  // Slack
  /xox[baprs]-[0-9]{8,}-[A-Za-z0-9-]{10,}/,
  /xapp-[0-9A-Za-z-]{20,200}/,
  /xoxa-[0-9A-Za-z-]{20,200}/,
  
  // Discord
  /[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}/,

  // Stripe
  /sk_live_[0-9a-zA-Z]{24}/,
  /rk_live_[0-9a-zA-Z]{24}/,

  // OpenAI / Anthropic / LLaMA / HuggingFace
  /sk-[A-Za-z0-9]{32,48}/,
  /hf_[A-Za-z0-9]{35,80}/,
  /anthropic-[A-Za-z0-9-]{30,80}/,

  // Cloudflare
  /cf_[A-Za-z0-9]{40,}/,

  // Twilio
  /SK[0-9a-fA-F]{32}/,

  // SendGrid
  /SG\.[A-Za-z0-9_-]{20,200}/,

  // JSON Web Tokens (JWT)
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,

  // Private Keys
  /-----BEGIN(?:[A-Z ]+)?PRIVATE KEY-----[\s\S]+?-----END(?:[A-Z ]+)?PRIVATE KEY-----/,

  // SSH Keys
  /ssh-rsa AAAA[0-9A-Za-z+/]{100,}\s*[A-Za-z0-9@._-]*/,

  // Stripe Signing Secret
  /whsec_[A-Za-z0-9]{32,}/,

  // Databricks
  /dapi[a-zA-Z0-9]{32}/,

  // Heroku
  /heroku_[A-Za-z0-9]{32}/,

  // HashiCorp Vault
  /hvs\.[A-Za-z0-9]{24,80}/,

  // Azure
  /[A-Za-z0-9]{8}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{12}/,  // AAD Secure token format

  // Miscelanious
  /\btoken\s*[:=]\s*['"][A-Za-z0-9_\-]{10,200}['"]/i,
  /\bapi[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{10,200}['"]/i,
  /\bsecret\s*[:=]\s*['"][A-Za-z0-9_\-]{10,200}['"]/i,
  /\bpassword\s*[:=]\s*['"][^'"]{4,200}['"]/i,
  /\bclient[_-]?secret\b\s*[:=]\s*['"][A-Za-z0-9_-]{10,200}['"]/i
];


const ALL_PATTERNS = [
  { risk: 'CRITICAL', patterns: CRITICAL_PATTERNS }
];

const foundKeys = new Map(); // Use a Map to store unique keys and their highest risk

const scanText = (text, sourceUrl) => {
  // Broad scan for potential keys first for efficiency
  const potentialKeys = text.matchAll(/([A-Za-z0-9_\-]{25,120}|[A-Za-z0-9+\/]{35,}={0,2})/g);

  for (const match of potentialKeys) {
    const key = match[1].trim();

    // 1. Filter out keys that are already found
    if (foundKeys.has(key)) {
      continue; // Skip if too short or already found
    }

    // 2. Only check for CRITICAL patterns and add them if they match.
    if (CRITICAL_PATTERNS.some(p => p.test(key))) {
      foundKeys.set(key, {
        risk: 'CRITICAL',
        key: key,
        source: sourceUrl
      });
    }
  }
};

// This object holds the results of the scan for this specific tab.
// It's provided to the popup when requested.
let findingsCache = { lastScan: [], scannedFiles: [] };

async function runScan() {
  // Check if the current domain is excluded before running the scan.
  const { excludedDomains = [] } = await chrome.storage.sync.get({ excludedDomains: [] });
  const currentHostname = window.location.hostname;

  if (excludedDomains.some(domain => currentHostname.includes(domain))) {
    console.log(`Key Scanner: Skipping scan because "${currentHostname}" is in the exclusion list.`);
    return; // Abort the scan
  }

  console.log("Key Scanner: Starting scan...");

  const scannedScripts = new Set();

  const processScript = async (scriptUrl) => {
    if (!scriptUrl || scannedScripts.has(scriptUrl)) {
      return;
    }
    scannedScripts.add(scriptUrl);
    try {
      // Ask the background script to fetch the URL to bypass CORS
      const response = await chrome.runtime.sendMessage({ type: "FETCH_SCRIPT", url: scriptUrl });

      if (response && response.success) {
        const text = response.text;
        scanText(text, scriptUrl);
      } else {
        // Log the error if the background script also failed
        console.warn(`Key Scanner: Background fetch failed for ${scriptUrl}`, response?.error);
      }
    } catch (error) {
      console.warn(`Key Scanner: Failed to fetch or scan ${scriptUrl}`, error);
    }
  };

  // --- Scan Phase 1: Scan all script tags visible in the DOM.
  const scriptTags = document.querySelectorAll('script[src]');
  for (const tag of scriptTags) {
    await processScript(tag.src);
  }

  // --- Scan Phase 2: Scan the main HTML document itself.
  // This finds inline scripts and keys hardcoded in the HTML.
  const htmlText = document.documentElement.outerHTML;
  scanText(htmlText, location.href);

  // --- Scan Phase 3: Find and scan "hidden" JS files (loaded dynamically).
  const hiddenScriptMatches = htmlText.matchAll(/['"](\/[^'"]+\.js(?:\?[^'"]*)?)['"]/g);
  for (const match of hiddenScriptMatches) {
    const scriptPath = new URL(match[1], location.origin).href;
    await processScript(scriptPath);
  }

  // --- Finalization Phase ---
  const uniqueFindings = Array.from(foundKeys.values());

  console.log(`Key Scanner: Found ${uniqueFindings.length} potential keys across ${scannedScripts.size} files.`);

  // Sort by risk for the popup display
  const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  uniqueFindings.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
  
  // Always update the cache with the latest scan results.
  findingsCache = {
    lastScan: uniqueFindings,
    scannedFiles: Array.from(scannedScripts)
  };

  if (uniqueFindings.length > 0) {
    chrome.runtime.sendMessage({ type: "FOUND_KEYS", count: uniqueFindings.length });
  }
}

// Run the scan once the document is fully loaded
runScan();

// Listen for messages from other parts of the extension.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_SCAN_RESULTS") { 
    // Popup is asking for data
    sendResponse(findingsCache);
  } else if (msg.type === "SHOW_RESULTS_BANNER") {
    // Background script is telling us to show the banner
    showInPageBanner(msg.count, msg.tabId);
  }
});

// Injects a banner at the top of the page to alert the user.
function showInPageBanner(count, tabId) {
  // Avoid creating duplicate banners
  if (document.getElementById('key-scanner-banner')) {
    return;
  }

  const banner = document.createElement('div');
  banner.id = 'key-scanner-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background-color: #d9534f;
    color: white;
    padding: 12px;
    font-family: Arial, sans-serif;
    font-size: 16px;
    z-index: 999999;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
    box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    border-bottom: 1px solid #a94442;
  `;

  banner.innerHTML = `
    <span>🚨 <strong>Secret Hunter:</strong> ${count} potential secret(s) found on this page. Click the extension icon or the desktop notification to see results.</span>
    <button id="key-scanner-close-btn" style="position: absolute; right: 15px; background: none; border: none; color: white; font-size: 24px; cursor: pointer; line-height: 1;">&times;</button>
  `;

  document.body.prepend(banner);

  // Event listener for the close button
  document.getElementById('key-scanner-close-btn').addEventListener('click', () => {
    banner.remove();
  });
}
