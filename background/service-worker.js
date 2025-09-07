import { analyzeForPhishing } from '../api/phishing-detection.js';
import { checkUrlSafety } from '../api/safebrowsing.js';
import { scanUrlWithVirusTotal } from '../api/virustotal.js';

// Initialize storage with default values
chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.sync.set({
    enablePhishing: true,
    enableLinkCheck: true,
    enableNotifications: true,
    scanContacts: false,
    scanImages: false,
    emailsScanned: 0,
    threatsBlocked: 0,
    lastScanTime: 0,
    scanHistory: []
  });
});

// Message handler for content script communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeEmail") {
    analyzeEmailContent(request.content).then(result => {
      updateScanStats(result.isThreat, request.content, result.trustScore, result.warnings);
      sendResponse(result);
    });
    return true; // Indicates async response
  }
  
  if (request.action === "manualScan") {
    handleManualScan(sender.tab, request.options).then(result => {
      sendResponse(result);
    });
    return true; // Indicates async response
  }
  
  if (request.action === "getScanHistory") {
    chrome.storage.sync.get('scanHistory', ({ scanHistory }) => {
      sendResponse({ history: scanHistory || [] });
    });
    return true;
  }
});

/**
 * Analyzes email content for security threats
 * @param {Object} emailContent - Email content {sender, subject, snippet}
 * @returns {Promise<Object>} - Analysis results
 */
async function analyzeEmailContent(emailContent) {
  let score = 100;
  let warnings = [];
  let isThreat = false;

  const settings = await chrome.storage.sync.get([
    'enablePhishing', 
    'enableLinkCheck',
    'scanContacts'
  ]);

  // Skip scanning for trusted contacts if enabled
  if (settings.scanContacts && isTrustedContact(emailContent.sender)) {
    return {
      trustScore: 100,
      warnings: [],
      isThreat: false
    };
  }

  // Phishing detection
  if (settings.enablePhishing !== false) {
    const phishingAnalysis = analyzeForPhishing(emailContent);
    if (phishingAnalysis.isPhishing) {
      score -= phishingAnalysis.confidence;
      warnings.push(`Phishing detected (confidence: ${phishingAnalysis.confidence}%)`);
      isThreat = true;
    }
  }

  // Link safety checks
  if (settings.enableLinkCheck !== false) {
    const links = extractLinks(emailContent.snippet);
    for (const link of links) {
      try {
        const linkSafety = await checkUrlSafety(link);
        if (!linkSafety.safe) {
          score -= 30;
          warnings.push(`Unsafe link: ${link} (${linkSafety.threats?.join(', ') || 'malicious'})`);
          isThreat = true;
          continue; // Skip VirusTotal if already unsafe
        }
        
        const vtResult = await scanUrlWithVirusTotal(link);
        if (vtResult.maliciousCount > 0) {
          score -= 10 * vtResult.maliciousCount;
          warnings.push(`VirusTotal: ${vtResult.maliciousCount} vendors flagged this URL`);
          isThreat = true;
        }
      } catch (error) {
        console.error(`Link analysis failed for ${link}:`, error);
        warnings.push(`Security check failed for link: ${link}`);
      }
    }
  }

  return {
    trustScore: Math.max(0, Math.min(100, score)),
    warnings,
    isThreat
  };
}

/**
 * Updates scan statistics and history
 * @param {boolean} isThreat - Whether threat was detected
 * @param {Object} emailContent - Email content for history
 */
async function updateScanStats(isThreat, emailContent, trustScore, warnings) {
  const data = await chrome.storage.sync.get([
    'emailsScanned', 
    'threatsBlocked', 
    'scanHistory'
  ]);
  
  const now = Date.now();
  const newStats = {
    emailsScanned: (data.emailsScanned || 0) + 1,
    lastScanTime: now
  };
  
  // Add to scan history (keep last 100 entries)
  const historyEntry = {
    ...emailContent,
    timestamp: now,
    trustScore: Math.max(0, Math.min(100, score)),
    isThreat,
    warnings : warnings
  };
  
  const scanHistory = [
    historyEntry,
    ...(data.scanHistory || []).slice(0, 99)
  ];
  
  if (isThreat) {
    newStats.threatsBlocked = (data.threatsBlocked || 0) + 1;
    notifyUser(emailContent.sender, emailContent.subject);
  }
  
  await chrome.storage.sync.set({ ...newStats, scanHistory });
}

/**
 * Notifies user about detected threat
 * @param {string} sender - Email sender
 * @param {string} subject - Email subject
 */
function notifyUser(sender, subject) {
  chrome.storage.sync.get('enableNotifications', (settings) => {
    if (settings.enableNotifications !== false) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'assets/icon48.png',
        title: 'Potential Threat Detected',
        message: `From: ${sender}\nSubject: ${subject}`,
        contextMessage: 'Click to view details',
        buttons: [{ title: 'Show Email' }]
      });
    }
  });
}

/**
 * Handles manual scan requests
 * @param {Tab} tab - Active browser tab
 * @param {Object} options - Scan options
 */
async function handleManualScan(tab, options) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: manualScanEmails,
      args: [options]
    });
    return { success: true };
  } catch (error) {
    console.error('Manual scan failed:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Extracts links from text
 * @param {string} text - Text content
 * @returns {string[]} - Array of URLs
 */
function extractLinks(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(urlRegex) || [];
}

/**
 * Checks if sender is trusted contact
 * @param {string} sender - Email sender
 * @returns {boolean} - Trust status
 */
function isTrustedContact(sender) {
  // Implement your trusted contacts logic
  return false;
}

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { action: "highlightThreats" });
    }
  });
});

// Daily update check
chrome.alarms.create('dailyUpdate', { periodInMinutes: 1440 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'dailyUpdate') {
    checkForUpdates();
  }
});

async function checkForUpdates() {
  // Implementation for update checks
}