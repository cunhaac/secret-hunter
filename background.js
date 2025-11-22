// A prefix for our notifications to distinguish them from other extension notifications.
const NOTIFICATION_PREFIX = "key-scanner-notification-";

chrome.runtime.onInstalled.addListener(() => {
  // Programmatically set the icon path to ensure it's loaded correctly,
  // as manifest declarations for .ico files can be unreliable.
  chrome.action.setIcon({
    path: {
      "16": "icons/favicon.ico",
      "48": "icons/favicon.ico",
      "128": "icons/favicon.ico"
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "FOUND_KEYS") {
    const tabId = sender.tab.id;
    const notificationId = `${NOTIFICATION_PREFIX}${tabId}`;

    // Set the "!" badge on the specific tab's icon.
    chrome.action.setBadgeText({ text: "!", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#d9534f" });

    // Create a persistent notification that stays until the user interacts with it.
    chrome.notifications.create(notificationId, {
      type: "basic",
      iconUrl: "icons/favicon.ico",
      title: "Potential Secret Keys Found!",
      message: `${msg.count} potential secrets detected. Click here to see the results.`,
      priority: 2,
      requireInteraction: true,
    });

    // Also, tell the content script to show an in-page banner
    chrome.tabs.sendMessage(tabId, { type: "SHOW_RESULTS_BANNER", count: msg.count, tabId: tabId });
  } else if (msg.type === "FETCH_SCRIPT") {
    // The content script is asking us to fetch a script's content
    // because it's running into CORS issues.
    fetch(msg.url, { credentials: "omit" })
      .then(response => {
        if (response.ok) {
          return response.text();
        }
        throw new Error(`Failed to fetch with status: ${response.status}`);
      })
      .then(text => sendResponse({ success: true, text: text }))
      .catch(error => sendResponse({ success: false, error: error.message }));

    // Return true to indicate that we will send a response asynchronously.
    return true;
  }
});

// Listen for clicks on the notification
chrome.notifications.onClicked.addListener((clickedNotificationId) => {
  // Check if the clicked notification is one of ours.
  if (clickedNotificationId.startsWith(NOTIFICATION_PREFIX)) {
    // Extract the tabId from the notification ID.
    const tabId = parseInt(clickedNotificationId.replace(NOTIFICATION_PREFIX, ""), 10);

    // Create a new popup window with the results
    chrome.windows.create({
      url: `popup.html?tabId=${tabId}&source=notification`, // Pass the tabId to the popup
      type: "popup",
      width: 340,
      height: 500
    });

    // Clear the notification once it's been clicked
    chrome.notifications.clear(clickedNotificationId);
  }
});