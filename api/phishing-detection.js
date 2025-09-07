// Heuristic-based phishing detection
const PHISHING_KEYWORDS = [
    'urgent', 'verify', 'account', 'suspended', 'password', 'login',
    'security', 'update', 'bank', 'paypal', 'irs', 'social security',
    'limited time', 'offer', 'click here', 'confirm', 'immediately',
    'action required', 'dear customer', 'dear user'
];

const URGENCY_PHRASES = [
    'immediately', 'urgent', 'right away', 'within 24 hours'
];

const SUSPICIOUS_DOMAINS = [
    'paypai.com', 'amaz0n.com', 'appleid.com', 'netflix.com',
    'micr0soft.com', 'g00gle.com', 'faceb00k.com'
];

/**
 * Analyzes email content for phishing indicators
 * @param {Object} email - Email content {sender, subject, snippet}
 * @returns {Object} - Analysis results
 */
export function analyzeForPhishing(email) {
    const sender = email.sender?.toLowerCase() || '';
    const subject = email.subject?.toLowerCase() || '';
    const body = email.snippet?.toLowerCase() || '';
    
    // 1. Check sender domain
    const senderDomain = extractDomain(sender);
    const domainRisk = SUSPICIOUS_DOMAINS.some(domain => 
        senderDomain.includes(domain.replace('.com', ''))
    );
    
    // 2. Count phishing keywords
    const keywordCount = PHISHING_KEYWORDS.reduce((count, keyword) => 
        count + (subject.includes(keyword)) || body.includes(keyword) ? 1 : 0, 0);
    
    // 3. Check for urgency
    const hasUrgency = URGENCY_PHRASES.some(phrase => 
        subject.includes(phrase) || body.includes(phrase));
    
    // 4. Link mismatch detection
    const linkMismatch = detectLinkMismatch(body);
    
    // Calculate confidence score
    const confidence = calculateConfidence(
        domainRisk, 
        keywordCount, 
        hasUrgency, 
        linkMismatch
    );
    
    return {
        isPhishing: confidence > 40,
        confidence,
        reasons: [
            domainRisk && `Suspicious sender domain: ${senderDomain}`,
            keywordCount > 0 && `${keywordCount} phishing keywords detected`,
            hasUrgency && "Urgency language detected",
            linkMismatch && "Link text mismatch detected"
        ].filter(Boolean)
    };
}

function extractDomain(email) {
    if (!email.includes('@')) return '';
    return email.split('@')[1];
}

function detectLinkMismatch(text) {
    // Placeholder for actual implementation
    return false;
}

function calculateConfidence(domainRisk, keywordCount, hasUrgency, linkMismatch) {
    let score = 0;
    if (domainRisk) score += 30;
    if (keywordCount > 0) score += Math.min(50, keywordCount * 10);
    if (hasUrgency) score += 20;
    if (linkMismatch) score += 25;
    return Math.min(100, score);
}