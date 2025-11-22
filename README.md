# Secret Hunter

![Project Icon](icons/icon.png)

*Disclaimer: Vibe Coding*

A Chrome extension that automatically scans web pages for accidentally exposed API keys, tokens, and other secrets.

## Features

- **Automatic Scanning:** Scans all visited pages for potential secrets in JavaScript files and inline HTML.
- **Comprehensive Patterns:** Uses a curated list of regular expressions to detect secrets from dozens of services like AWS, Google Cloud, GitHub, Stripe, and more.
- **Real-time Alerts:** Immediately notifies you with a browser notification and an icon badge when a potential secret is found.
- **Detailed Popup:** Click the extension icon to see a detailed list of found keys, their source, and a list of all files scanned on the page.
- **Domain Exclusion:** Easily add domains to an exclusion list to prevent the scanner from running on trusted or internal sites.

## How It Works

The extension runs in the background and performs the following actions on each page you visit:

1.  Checks if the current site's domain is in your exclusion list.
2.  If not excluded, it fetches and scans all external and inline JavaScript files.
3.  It also scans the page's main HTML content for hardcoded keys.
4.  If a potential secret is found, it triggers a desktop notification and displays a "!" badge on the extension icon.

## Popup Preview

The popup provides a clear overview of the scan results and allows you to manage your excluded domains.

![Popup Preview](popup.png)

## Installation

Since this extension is not on the Chrome Web Store, you can load it locally in developer mode.

1.  **Download or Clone:** Download this repository to your local machine.
2.  **Open Chrome Extensions:** Open Google Chrome and navigate to `chrome://extensions`.
3.  **Enable Developer Mode:** Turn on the "Developer mode" toggle in the top-right corner.
4.  **Load Unpacked:** Click the "Load unpacked" button.
5.  **Select Folder:** Select the directory where you downloaded the extension files.

The Secret Hunter icon should now appear in your browser's toolbar, and it will start scanning pages automatically.