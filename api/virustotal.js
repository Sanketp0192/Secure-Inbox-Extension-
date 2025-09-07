// VirusTotal API integration with key rotation
const API_KEYS = [
    'YOUR_API_KEY_HERE',  // ← Replace with your actual key
    'YOUR_API_KEY_HERE'   // ← Replace with your actual key
];
let currentKeyIndex = 0;
const CACHE = new Map();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

/**
 * Scans a URL using VirusTotal API
 * @param {string} url - URL to scan
 * @returns {Promise<Object>} - Scan results
 */
export async function scanUrlWithVirusTotal(url) {
    // Check cache first
    if (CACHE.has(url) && Date.now() - CACHE.get(url).timestamp < CACHE_DURATION) {
        return CACHE.get(url).data;
    }

    const apiKey = API_KEYS[currentKeyIndex];
    const headers = {
        'x-apikey': apiKey,
        'Accept': 'application/json'
    };

    try {
        // Step 1: Submit URL for analysis
        const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                ...headers,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        if (!submitResponse.ok) {
            if (submitResponse.status === 429) { // Quota exceeded
                return rotateKeyAndRetry(url);
            }
            throw new Error(`Submission failed: ${submitResponse.status}`);
        }

        const submitData = await submitResponse.json();
        const analysisId = submitData.data.id;

        // Step 2: Wait and retrieve analysis report
        await new Promise(resolve => setTimeout(resolve, 3000));
        const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers
        });

        if (!analysisResponse.ok) {
            if (analysisResponse.status === 429) {
                return rotateKeyAndRetry(url);
            }
            throw new Error(`Analysis failed: ${analysisResponse.status}`);
        }

        const analysisData = await analysisResponse.json();
        const result = processAnalysis(analysisData);

        // Cache result
        CACHE.set(url, {
            data: result,
            timestamp: Date.now()
        });

        return result;
    } catch (error) {
        console.error('VirusTotal scan error:', error);
        return {
            safe: true,
            error: error.message,
            maliciousCount: 0
        };
    }
}

function processAnalysis(analysisData) {
    const attributes = analysisData.data.attributes;
    const stats = attributes.stats || {};
    const maliciousCount = stats.malicious || 0;
    
    return {
        safe: maliciousCount === 0,
        maliciousCount,
        totalEngines: Object.values(stats).reduce((sum, count) => sum + count, 0),
        engines: attributes.results,
        lastAnalysis: new Date(attributes.date * 1000).toISOString()
    };
}

async function rotateKeyAndRetry(url) {
    // Rotate to next key
    currentKeyIndex = (currentKeyIndex + 1) % API_KEYS.length;
    
    if (currentKeyIndex === 0) {
        throw new Error('All VirusTotal API keys exhausted');
    }
    
    console.log(`Rotating to VirusTotal key ${currentKeyIndex + 1}`);
    return scanUrlWithVirusTotal(url);
}
