// Wait for Gmail to fully load
function waitForGmail() {
  return new Promise(resolve => {
    if (document.querySelector('[role="main"]')) {
      resolve();
    } else {
      const observer = new MutationObserver(() => {
        if (document.querySelector('[role="main"]')) {
          observer.disconnect();
          resolve();
        }
      });
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }
  });
}

// Get all visible email elements
function getEmailElements() {
  return document.querySelectorAll('[role="main"] .zA, [role="main"] .x7, [role="main"] .BltHke');
}

// Extract email content from element
function extractEmailContent(emailElement) {
  return {
    sender: emailElement.querySelector('[email]')?.getAttribute('email') || 
           emailElement.querySelector('.yW span')?.textContent || 
           emailElement.querySelector('.afn')?.getAttribute('email') || '',
    subject: emailElement.querySelector('.y6 span')?.textContent || 
            emailElement.querySelector('.bog span')?.textContent || 
            emailElement.querySelector('.bqe')?.textContent || '',
    snippet: emailElement.querySelector('.y2')?.textContent || 
            emailElement.querySelector('.yP')?.textContent || 
            emailElement.querySelector('.bog span')?.textContent || '',
    date: emailElement.querySelector('.xW.xY')?.textContent || 
         emailElement.querySelector('.xW')?.textContent || 
         emailElement.querySelector('.bqe')?.nextElementSibling?.textContent || ''
  };
}

// Process all visible emails
async function processEmailElements() {
  const emailElements = getEmailElements();
  
  for (const emailElement of emailElements) {
    if (emailElement.dataset.trustAnalyzed === 'true') continue;
    emailElement.dataset.trustAnalyzed = 'true';
    
    try {
      const emailContent = extractEmailContent(emailElement);
      const { trustScore, warnings, isThreat } = await chrome.runtime.sendMessage({
        action: "analyzeEmail",
        content: emailContent
      });
      
      addTrustBadge(emailElement, trustScore);
      
      if (warnings.length > 0) {
        addWarningBanner(emailElement, warnings, trustScore);
      }
      
      if (isThreat) {
        emailElement.classList.add('potential-threat');
      }
    } catch (error) {
      console.error('Error processing email:', error);
    }
  }
}

// Add trust badge to email element
function addTrustBadge(emailElement, trustScore) {
  // Remove existing badges
  const existingBadge = emailElement.querySelector('.trust-badge');
  if (existingBadge) existingBadge.remove();
  
  const badge = document.createElement('div');
  badge.className = 'trust-badge';
  
  // Create circular progress
  const progress = document.createElement('div');
  progress.className = 'trust-progress';
  progress.style.setProperty('--progress', trustScore);
  
  // Create score display
  const score = document.createElement('div');
  score.className = 'trust-score';
  score.textContent = trustScore;
  
  // Tooltip with details
  const tooltip = document.createElement('div');
  tooltip.className = 'trust-tooltip';
  tooltip.textContent = `Trust Score: ${trustScore}/100`;
  
  badge.appendChild(progress);
  badge.appendChild(score);
  badge.appendChild(tooltip);
  
  // Add to subject area
  const subjectArea = emailElement.querySelector('.y6') || 
                     emailElement.querySelector('.bog') || 
                     emailElement.querySelector('.bqe');
  
  if (subjectArea) {
    subjectArea.appendChild(badge);
  }
}

// Add warning banner to email element
function addWarningBanner(emailElement, warnings, trustScore) {
  // Remove existing banners
  const existingBanner = emailElement.querySelector('.warning-banner');
  if (existingBanner) existingBanner.remove();
  
  const banner = document.createElement('div');
  banner.className = `warning-banner ${trustScore < 50 ? 'high-risk' : ''}`;
  
  // Warning icon
  const icon = document.createElement('div');
  icon.className = 'warning-icon';
  icon.innerHTML = '⚠️';
  
  // Warning text
  const text = document.createElement('div');
  text.className = 'warning-text';
  text.textContent = warnings.length > 1 ? 
    `${warnings.length} security issues detected` : 
    warnings[0];
  
  // Details button
  const detailsBtn = document.createElement('button');
  detailsBtn.className = 'security-scan-button';
  detailsBtn.textContent = 'Details';
  detailsBtn.onclick = () => showDetailedWarnings(warnings);
  
  banner.appendChild(icon);
  banner.appendChild(text);
  banner.appendChild(detailsBtn);
  
  // Add to snippet area
  const snippetArea = emailElement.querySelector('.y2')?.parentElement || 
                     emailElement.querySelector('.yP')?.parentElement ||
                     emailElement.querySelector('.bog')?.parentElement;
  
  if (snippetArea) {
    snippetArea.insertBefore(banner, snippetArea.firstChild);
  }
}

// Show detailed warnings in alert
function showDetailedWarnings(warnings) {
  alert("SECURITY WARNINGS:\n\n" + warnings.join('\n\n'));
}

// Handle manual scan trigger
document.addEventListener('manualScanTriggered', processEmailElements);

// Initialize extension
async function initExtension() {
  await waitForGmail();
  processEmailElements();
  
  // Watch for new emails
  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length) {
        processEmailElements();
      }
    }
  });
  
  const mainArea = document.querySelector('[role="main"]');
  if (mainArea) {
    observer.observe(mainArea, {
      childList: true,
      subtree: true
    });
  }
  
  // Watch for view changes
  window.addEventListener('hashchange', processEmailElements);
}

// Start when ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initExtension);
} else {
  initExtension();
}