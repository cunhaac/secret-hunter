document.addEventListener("DOMContentLoaded", () => {
  loadExcludedDomains();

  const urlParams = new URLSearchParams(window.location.search);
  const tabIdFromUrl = urlParams.get('tabId');

  if (tabIdFromUrl) {
    // This window was opened by clicking a notification.
    fetchAndDisplayResults(parseInt(tabIdFromUrl, 10));
  } else {
    // Otherwise, find the current active tab (for regular toolbar clicks)
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length > 0) {
        fetchAndDisplayResults(tabs[0].id);
      } else {
        document.getElementById("results").textContent = "Could not find active tab.";
      }
    });
  }

  document.getElementById("add-domain-btn").addEventListener("click", () => {
    const domainInput = document.getElementById("domain-to-exclude");
    const domain = domainInput.value.trim();
    if (domain) {
      addDomainToExclusionList(domain);
      domainInput.value = "";
    }
  });

  // Use event delegation for remove buttons
  document.getElementById("excluded-domains-list").addEventListener("click", handleRemoveDomain);
});

function fetchAndDisplayResults(activeTabId) {
    chrome.tabs.sendMessage(activeTabId, { type: "GET_SCAN_RESULTS" }, (response) => {
      if (chrome.runtime.lastError) {
        // This can happen if the content script hasn't been injected yet (e.g., on a new tab page)
        document.getElementById("results").textContent = "Page has not been scanned. Please reload the page.";
        document.getElementById("scanned-files-list").innerHTML = "<li>N/A</li>";
        return;
      }

      const { lastScan, scannedFiles } = response;
      const resultsContainer = document.getElementById("results");
      const filesContainer = document.getElementById("scanned-files-list");

      // Display found keys
      if (!lastScan || lastScan.length === 0) {
        resultsContainer.textContent = "No keys found on this page.";
      } else {
        resultsContainer.innerHTML = lastScan.map(item => {
          const displaySource = item.source.length > 40 ? `...${item.source.slice(-37)}` : item.source;
          return `
            <div class="key ${item.risk}">
              <strong>${item.risk}</strong><br>
              <small title="${item.key}">${item.key.length > 50 ? `${item.key.substring(0, 25)}...${item.key.substring(item.key.length - 25)}` : item.key}</small><br>
              <em>Source: <a href="${item.source}" target="_blank" title="${item.source}">${displaySource}</a></em>
            </div>`;
        }).join("");
      }

      // Display scanned files for debugging
      filesContainer.innerHTML = (scannedFiles && scannedFiles.length > 0)
        ? scannedFiles.map(file => `<li title="${file}">${file.length > 100 ? '...' + file.slice(-97) : file}</li>`).join("")
        : "<li>No script files were processed.</li>";
    });
}

function renderExcludedDomains(domains = []) {
  const list = document.getElementById("excluded-domains-list");
  list.innerHTML = domains.map(domain => `
    <li>
      <span>${domain}</span>
      <button class="remove-btn" data-domain="${domain}">&times;</button>
    </li>
  `).join("");
}

function loadExcludedDomains() {
  chrome.storage.sync.get({ excludedDomains: [] }, (data) => {
    renderExcludedDomains(data.excludedDomains);
  });
}

function addDomainToExclusionList(domain) {
  chrome.storage.sync.get({ excludedDomains: [] }, (data) => {
    const domains = new Set(data.excludedDomains);
    domains.add(domain);
    chrome.storage.sync.set({ excludedDomains: Array.from(domains) }, () => {
      renderExcludedDomains(Array.from(domains));
    });
  });
}

function handleRemoveDomain(event) {
  if (event.target.classList.contains("remove-btn")) {
    const domainToRemove = event.target.dataset.domain;
    if (domainToRemove) {
      removeDomainFromExclusionList(domainToRemove);
    }
  }
}

function removeDomainFromExclusionList(domainToRemove) {
  chrome.storage.sync.get({ excludedDomains: [] }, (data) => {
    let domains = data.excludedDomains.filter(d => d !== domainToRemove);
    chrome.storage.sync.set({ excludedDomains: domains }, () => {
      renderExcludedDomains(domains);
    });
  });
}