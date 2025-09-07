// Background helper functions

/**
 * Triggers a manual scan of all visible emails
 * @param {Object} options - Scan options
 */
export function manualScanEmails(options) {
  const emailElements = document.querySelectorAll('[role="main"] .zA, [role="main"] .x7');
  emailElements.forEach(el => el.dataset.trustAnalyzed = 'false');
  
  const event = new Event('manualScanTriggered');
  document.dispatchEvent(event);
  
  return { count: emailElements.length };
}

/**
 * Highlights all detected threats in the inbox
 */
export function highlightThreats() {
  document.querySelectorAll('.potential-threat').forEach(el => {
    el.style.animation = 'threat-pulse 2s infinite';
    setTimeout(() => {
      el.style.animation = '';
    }, 5000);
  });
}

// For demonstration purposes - implement these based on your needs
export function addTrustedContact(email) {
  // Add to trusted contacts list
}

export function removeTrustedContact(email) {
  // Remove from trusted contacts list
}