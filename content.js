// --------------------
// CRITICAL patterns
// --------------------
const CRITICAL_PATTERNS = [

  // ========================
  // AMAZON AWS
  // ========================
  /AKIA[0-9A-Z]{16}/,                                    // Access Key ID
  /ASIA[0-9A-Z]{16}/,                                    // STS Key
  /A3T[A-Z0-9]{16}/,                                     // Device Auth
  /AKTP[0-9A-Z]{16}/,                                    // Finance Key

  // AWS Secret Keys
  /(?:aws_)?secret(?:_access)?_key[^A-Za-z0-9]*([A-Za-z0-9\/+=]{40})/i,

  // AWS Session Tokens (base64-ish)
  /AQoDYXdzE[\w+=\/]{30,}/,

  
  // ========================
  // GOOGLE CLOUD
  // ========================
  /ya29\.[0-9A-Za-z\-_]+/,                               // OAuth Google Access Token
  /[0-9a-f]{64}_apps\.googleusercontent\.com/,           // GCP OAuth Client Secret

  // GCP service account private key ID
  /"private_key_id":\s*"[0-9a-f]{40}"/,


  // ========================
  // FIREBASE
  // ========================
  /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/,             // FCM Server Key


  // ========================
  // GITHUB / GITLAB
  // ========================
  /gh[pousr]_[A-Za-z0-9]{36}/,                           // GitHub Tokens
  /glpat-[A-Za-z0-9\-]{20,50}/,                          // GitLab Access Token
  /glptt-[A-Za-z0-9\-]{20,50}/,                          // GitLab Trigger Token


  // ========================
  // SLACK
  // ========================
  /xox[baprs]-[0-9]{8,}-[A-Za-z0-9-]{10,}/,
  /xapp-[0-9A-Za-z-]{20,200}/,
  /xoxa-[0-9A-Za-z-]{20,200}/,


  // ========================
  // DISCORD
  // ========================
  /[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}/,


  // ========================
  // STRIPE
  // ========================
  /sk_live_[0-9a-zA-Z]{24}/,
  /rk_live_[0-9a-zA-Z]{24}/,
  /whsec_[A-Za-z0-9]{32,}/,                              // Webhook Signing Secret


  // ========================
  // OPENAI / ANTHROPIC / HF / LLAMA
  // ========================
  /sk-[A-Za-z0-9]{32,48}/,
  /hf_[A-Za-z0-9]{35,80}/,
  /anthropic-[A-Za-z0-9-]{30,80}/,


  // ========================
  // CLOUDFLARE
  // ========================
  /cf_[A-Za-z0-9]{40,}/,


  // ========================
  // TWILIO
  // ========================
  /SK[0-9a-fA-F]{32}/,


  // ========================
  // SENDGRID
  // ========================
  /SG\.[A-Za-z0-9_-]{20,200}/,


  // ========================
  // DIGITALOCEAN
  // ========================
  /dop_v1_[A-Za-z0-9]{64}/,


  // ========================
  // LINODE
  // ========================
  /linode_[A-Za-z0-9]{64}/,


  // ========================
  // HASHICORP / TERRAFORM
  // ========================
  /hvs\.[A-Za-z0-9]{24,80}/,                              // Vault Token
  /tfe-[A-Za-z0-9]{36}/,                                  // Terraform Cloud Token


  // ========================
  // HEROKU
  // ========================
  /heroku_[A-Za-z0-9]{32}/,


  // ========================
  // AZURE
  // ========================
  /[A-Za-z0-9]{8}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{4}\.[A-Za-z0-9]{12}/,  // AAD secure token
  /"clientSecret":\s*"[A-Za-z0-9\._~\-\+\/]{20,100}"/,


  // ========================
  // ALGOLIA
  // ========================
  /[A-Za-z0-9]{32}-[A-Za-z0-9]{10}/,                      // Admin API keys often this format


  // ========================
  // MAILGUN
  // ========================
  /key-[0-9a-zA-Z]{32}/,


  // ========================
  // DATABASE CONNECTION STRINGS
  // ========================
  /mongodb(\+srv)?:\/\/[A-Za-z0-9._%\-]+:[^@]+@[A-Za-z0-9.\-]+(:[0-9]+)?\/[A-Za-z0-9._\-]+/,
  /postgres(?:ql)?:\/\/[A-Za-z0-9._%-]+:[^@]+@[A-Za-z0-9.\-]+(:[0-9]+)?\/[A-Za-z0-9._\-]+/,
  /redis:\/\/:[^@]+@[A-Za-z0-9.\-]+:[0-9]+/,
  /mysql:\/\/[A-Za-z0-9._%-]+:[^@]+@[A-Za-z0-9.\-]+\/[A-Za-z0-9._\-]+/,


  // ========================
  // JWT TOKENS
  // ========================
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,


  // ========================
  // PRIVATE KEYS
  // ========================
  /-----BEGIN(?:[ A-Z]+)?PRIVATE KEY-----[\s\S]+?-----END(?:[ A-Z]+)?PRIVATE KEY-----/,
  /-----BEGIN(?:[ A-Z]+)?RSA PRIVATE KEY-----[\s\S]+?-----END(?:[ A-Z]+)?RSA PRIVATE KEY-----/,
  /-----BEGIN(?:[ A-Z]+)?EC PRIVATE KEY-----[\s\S]+?-----END(?:[ A-Z]+)?EC PRIVATE KEY-----/,
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----/,


  // ========================
  // SSH KEYS
  // ========================
  /ssh-rsa AAAA[0-9A-Za-z+/]{100,}[\s]*(?:[A-Za-z0-9@._-]+)?/,
  /ssh-ed25519 AAAA[0-9A-Za-z+/]{50,}[\s]*(?:[A-Za-z0-9@._-]+)?/,
  /ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]{50,}/,


  // ========================
  // OAUTH / API TOKENS MISC
  // ========================
  /EAACEdEose0cBA[0-9A-Za-z]+/,                          // Facebook
  /AQA[A-Za-z0-9_-]{100,}/,                              // Generic OAuth long tokens
  /AAAA[A-Za-z0-9_-]{100,}/,                             // Very long opaque tokens

  
  // ========================
  // CLOUD MISC
  // ========================
  /dapi[a-zA-Z0-9]{32}/,                                 // Databricks
  /tokenv2\.[A-Za-z0-9\-_]{60,}/,                        // Supabase JWT-like keys


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
