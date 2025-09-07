// Google Safe Browsing API integration with key rotation
const API_KEYS = [
    ' ',  // ← Replace with your actual key
    ' '   // ← Replace with your actual key
];
let currentKeyIndex = 0;
const CACHE = new Map();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

/**
 * Checks URL safety using Google Safe Browsing
 * @param {string} url - URL to check
 * @returns {Promise<Object>} - Safety results
 */
export async function checkUrlSafety(url) {
    // Check cache first
    if (CACHE.has(url) && Date.now() - CACHE.get(url).timestamp < CACHE_DURATION) {
        return CACHE.get(url).data;
    }

    const apiKey = API_KEYS[currentKeyIndex];
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    
    const requestBody = {
        client: {
            clientId: "secure-inbox-extension",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
        }
    };

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            if (response.status === 429) { // Quota exceeded
                return rotateKeyAndRetry(url);
            }
            throw new Error(`API request failed: ${response.status}`);
        }

        const data = await response.json();
        const result = processResponse(data);
        
        // Cache result
        CACHE.set(url, {
            data: result,
            timestamp: Date.now()
        });

        return result;
    } catch (error) {
        console.error('Safe Browsing check error:', error);
        return {
            safe: true,
            error: error.message,
            threats: []
        };
    }
}

function processResponse(data) {
    if (!data.matches || data.matches.length === 0) {
        return { safe: true, threats: [] };
    }
    
    return {
        safe: false,
        threats: data.matches.map(match => ({
            type: match.threatType,
            platform: match.platformType,
            url: match.threat.url
        }))
    };
}

async function rotateKeyAndRetry(url) {
    // Rotate to next key
    currentKeyIndex = (currentKeyIndex + 1) % API_KEYS.length;
    
    if (currentKeyIndex === 0) {
        throw new Error('All Safe Browsing API keys exhausted');
    }
    
    console.log(`Rotating to Safe Browsing key ${currentKeyIndex + 1}`);
    return checkUrlSafety(url);
}