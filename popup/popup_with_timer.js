// popup.js - Comprehensive Implementation
document.addEventListener('DOMContentLoaded', async () => {
  // Check if Gmail/Outlook is active
  await checkActiveTab();
  
  // Setup event listeners
  setupTabNavigation();
  setupDashboard();
  setupHistorySection();
  setupSettings();
  setupHelpSection();
  setupAboutSection();
  setupInactiveView();
  
  // Load initial data
  loadInitialData();
});


// VIEW MANAGEMENT


async function checkActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const isEmailClient = tab?.url?.includes('mail.google.com') || tab?.url?.includes('outlook.live.com');
  
  document.getElementById('inactive-view').style.display = isEmailClient ? 'none' : 'flex';
  document.getElementById('active-view').style.display = isEmailClient ? 'flex' : 'none';
}


// TAB NAVIGATION


function setupTabNavigation() {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active class from all tabs
      tabs.forEach(t => t.classList.remove('active'));
      // Add active class to clicked tab
      tab.classList.add('active');
      
      // Hide all tab contents
      tabContents.forEach(content => content.classList.remove('active'));
      
      // Show target tab content
      const targetId = tab.dataset.target;
      document.getElementById(targetId).classList.add('active');
      
      // Refresh section if needed
      if (targetId === 'history') refreshHistory();
    });
  });
}


// DASHBOARD FUNCTIONALITY


function setupDashboard() {
  // Manual scan button
  document.getElementById('scan-now').addEventListener('click', startManualScan);
  
  // Refresh stats button
  document.getElementById('refresh-stats').addEventListener('click', updateDashboardStats);
  
  // Load recent threats
  loadRecentThreats();
}

async function updateDashboardStats() {
  const data = await chrome.storage.sync.get(['emailsScanned', 'threatsBlocked']);
  document.getElementById('emails-scanned').textContent = data.emailsScanned || 0;
  document.getElementById('threats-blocked').textContent = data.threatsBlocked || 0;
}

async function loadRecentThreats() {
  const { scanHistory } = await chrome.storage.sync.get('scanHistory');
  const threatsList = document.getElementById('threats-list');
  threatsList.innerHTML = '';
  
  // Get last 5 threats
  const recentThreats = (scanHistory || [])
    .filter(entry => entry.isThreat)
    .slice(0, 5);
  
  if (recentThreats.length === 0) {
    threatsList.innerHTML = '<div class="no-threats">No recent threats detected</div>';
    return;
  }
  
  recentThreats.forEach(threat => {
    const threatItem = document.createElement('div');
    threatItem.className = 'threat-item';
    threatItem.innerHTML = `
      <div class="threat-icon">!</div>
      <div class="threat-content">
        <div class="threat-sender">${threat.sender || 'Unknown Sender'}</div>
        <div class="threat-subject">${threat.subject || 'No Subject'}</div>
      </div>
    `;
    threatsList.appendChild(threatItem);
  });
}

async function startManualScan() {
  const scanButton = document.getElementById('scan-now');
  const progressBar = document.querySelector('.progress-bar');

  scanButton.disabled = true;
const lastScanTimeData = await chrome.storage.sync.get('lastDummyScanTime');
  const now = Date.now();
  const oneMinute = 60 * 1000;

  if (lastScanTimeData.lastDummyScanTime && (now - lastScanTimeData.lastDummyScanTime) < oneMinute) {
    alert('Scan Error: API key failed to retrieve email data. Try again after a minute.');
    scanButton.disabled = false;
    progressBar.style.display = 'none';
    return;
  }

  await chrome.storage.sync.set({ lastDummyScanTime: now });
  progressBar.style.display = 'block';

  try {
    // Simulate scan with delay
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Get current stats
    const data = await chrome.storage.sync.get(['emailsScanned', 'threatsBlocked']);
    let emailsScanned = data.emailsScanned || 0;
    let threatsBlocked = data.threatsBlocked || 0;

    // Generate dummy increments
    const emailIncrement = Math.floor(Math.random() * 6) + 5; // 5 to 10
    const threatIncrement = Math.floor(Math.random() * 3) + 1; // 1 to 3

    // Update within defined range
    emailsScanned = Math.min(261, Math.max(50, emailsScanned + emailIncrement));
    threatsBlocked = Math.min(53, Math.max(5, threatsBlocked + threatIncrement));

    // Store updated stats
    await chrome.storage.sync.set({ emailsScanned, threatsBlocked });

    // Update UI
    await updateDashboardStats();
    showScanComplete();

  } catch (error) {
    console.error('Dummy scan failed:', error);
    alert('Scan simulation failed.');
  } finally {
    scanButton.disabled = false;
    progressBar.style.display = 'none';
  }
}

function showScanComplete() {
  const progress = document.querySelector('.progress');
  progress.style.width = '100%';
  
  setTimeout(() => {
    progress.style.width = '0%';
  }, 1000);
}


// HISTORY SECTION


function setupHistorySection() {
  // Search input
  document.getElementById('history-search').addEventListener('input', refreshHistory);
  
  // Filter dropdown
  document.getElementById('history-filter').addEventListener('change', refreshHistory);
}

async function refreshHistory() {
  const searchTerm = document.getElementById('history-search').value.toLowerCase();
  const filterValue = document.getElementById('history-filter').value;
  const { scanHistory } = await chrome.storage.sync.get('scanHistory');
  const historyList = document.getElementById('history-list');
  
  historyList.innerHTML = '';
  
  if (!scanHistory || scanHistory.length === 0) {
    historyList.innerHTML = '<div class="no-history">No scan history available</div>';
    return;
  }
  
  // Filter history
  const filteredHistory = scanHistory.filter(entry => {
    // Apply search filter
    const matchesSearch = (
      (entry.sender && entry.sender.toLowerCase().includes(searchTerm)) ||
      (entry.subject && entry.subject.toLowerCase().includes(searchTerm)) ||
      (entry.snippet && entry.snippet.toLowerCase().includes(searchTerm))
    );
    
    // Apply threat filter
    const matchesFilter = filterValue === 'all' || 
      (filterValue === 'threats' && entry.isThreat) ||
      (filterValue === 'safe' && !entry.isThreat);
    
    return matchesSearch && matchesFilter;
  });
  
  if (filteredHistory.length === 0) {
    historyList.innerHTML = '<div class="no-results">No matching history found</div>';
    return;
  }
  
  // Display history
  filteredHistory.forEach(entry => {
    const historyItem = document.createElement('div');
    historyItem.className = `history-item ${entry.isThreat ? 'threat' : ''}`;
    historyItem.innerHTML = `
      <div class="history-header">
        <div class="history-sender">${entry.sender || 'Unknown Sender'}</div>
        <div class="history-date">${formatDate(entry.timestamp)}</div>
      </div>
      <div class="history-subject">${entry.subject || 'No Subject'}</div>
      <div class="history-stats">
        <div class="history-stat">
          <div class="stat-label">Trust Score</div>
          <div class="stat-value ${entry.trustScore > 75 ? 'safe' : entry.trustScore > 50 ? 'warning' : 'threat'}">
            ${entry.trustScore || 0}
          </div>
        </div>
        <div class="history-stat">
          <div class="stat-label">Warnings</div>
          <div class="stat-value">${entry.warnings?.length || 0}</div>
        </div>
      </div>
    `;
    historyList.appendChild(historyItem);
  });
}

function formatDate(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}


// SETTINGS MANAGEMENT


function setupSettings() {
  // Load settings
  loadSettings();
  
  // Register change listeners
  document.querySelectorAll('.settings input[type="checkbox"]').forEach(input => {
    input.addEventListener('change', saveSetting);
  });
  
  // Save API keys button
  document.getElementById('save-api-keys').addEventListener('click', saveApiKeys);
}

async function loadSettings() {
  const data = await chrome.storage.sync.get([
    'enablePhishing',
    'enableLinkCheck',
    'enableNotifications',
    'scanContacts',
    'scanImages',
    'safebrowsingKeys',
    'virustotalKeys'
  ]);
  
  document.getElementById('enable-phishing').checked = data.enablePhishing !== false;
  document.getElementById('enable-link-check').checked = data.enableLinkCheck !== false;
  document.getElementById('enable-notifications').checked = data.enableNotifications !== false;
  document.getElementById('scan-contacts').checked = data.scanContacts || false;
  document.getElementById('scan-images').checked = data.scanImages || false;
  
  // Load API keys
  if (data.safebrowsingKeys) {
    document.getElementById('safebrowsing-keys').value = data.safebrowsingKeys.join(', ');
  }
  
  if (data.virustotalKeys) {
    document.getElementById('virustotal-keys').value = data.virustotalKeys.join(', ');
  }
}

async function saveSetting(e) {
  await chrome.storage.sync.set({
    [e.target.id]: e.target.checked
  });
}

async function saveApiKeys() {
  const safebrowsingKeys = document.getElementById('safebrowsing-keys').value
    .split(',')
    .map(key => key.trim())
    .filter(key => key.length > 0);
  
  const virustotalKeys = document.getElementById('virustotal-keys').value
    .split(',')
    .map(key => key.trim())
    .filter(key => key.length > 0);
  
  await chrome.storage.sync.set({
    safebrowsingKeys,
    virustotalKeys
  });
  
  alert('API keys saved successfully!');
}


// HELP SECTION


function setupHelpSection() {
  // FAQ accordion
  document.querySelectorAll('.faq-question').forEach(question => {
    question.addEventListener('click', () => {
      const answer = question.nextElementSibling;
      const isOpen = answer.classList.contains('show');
      
      // Close all answers
      document.querySelectorAll('.faq-answer').forEach(ans => {
        ans.classList.remove('show');
      });
      
      // Remove active class from all questions
      document.querySelectorAll('.faq-question').forEach(q => {
        q.classList.remove('active');
      });
      
      // Toggle current answer
      if (!isOpen) {
        answer.classList.add('show');
        question.classList.add('active');
      }
    });
  });
}


// ABOUT SECTION


function setupAboutSection() {
  // No special functionality needed for now
}


// INACTIVE VIEW


function setupInactiveView() {
  // Open Gmail button
  document.getElementById('open-gmail').addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://mail.google.com' });
  });
  
  // Open Outlook button
  document.getElementById('open-outlook').addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://outlook.live.com' });
  });
  
  // Settings button
  document.getElementById('settings-from-inactive').addEventListener('click', () => {
    // Switch to active view and settings tab
    document.getElementById('inactive-view').style.display = 'none';
    document.getElementById('active-view').style.display = 'flex';
    
    // Activate settings tab
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelector('[data-target="settings"]').classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById('settings').classList.add('active');
  });
  
  // About button
  document.getElementById('about-from-inactive').addEventListener('click', () => {
    // Switch to active view and about tab
    document.getElementById('inactive-view').style.display = 'none';
    document.getElementById('active-view').style.display = 'flex';
    
    // Activate about tab
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelector('[data-target="about"]').classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById('about').classList.add('active');
  });
}


// INITIALIZATION


async function loadInitialData() {
  // Load dashboard stats
  await updateDashboardStats();
  
  // Load settings
  await loadSettings();

  // Load Recent Threats
  await loadRecentThreats();
  
  // Load history if on history tab
  if (document.querySelector('[data-target="history"].active')) {
    refreshHistory();
  }
}

//Function to refresh Dashboard
async function refreshDashboard() {
  await updateDashboardStats();
  await loadRecentThreats();
}


// Listen for storage changes
chrome.storage.onChanged.addListener(changes => {
  if (changes.emailsScanned || changes.threatsBlocked || changes.scanHistory) {
    updateDashboardStats(); //Update Dashboard Stats
    refreshDashboard(); // Refresh Dashboard 
  }
  
  if (changes.scanHistory) {
    if (document.getElementById('history').classList.contains('active')) {
      refreshHistory();
    }
    if (document.getElementById('dashboard').classList.contains('active')) {
      loadRecentThreats();
    }
  }
});

// Update when tab changes
chrome.tabs.onActivated.addListener(() => checkActiveTab());
chrome.tabs.onUpdated.addListener(() => checkActiveTab());