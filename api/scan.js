export default async function handler(req, res) {
    // Replace with your actual GitHub Pages URL
    res.setHeader('Access-Control-Allow-Origin', 'https://yourname.github.io');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const API_KEY = process.env.VT_API_KEY;
    if (!API_KEY) return res.status(500).json({ error: 'API key not configured' });

    const { endpoint, method = 'GET', body, isFormData } = req.body;

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
            method,
            headers: {
                "x-apikey": API_KEY,
                ...(isFormData
                    ? { "content-type": "application/x-www-form-urlencoded" }
                    : {}
                )
            },
            ...(body ? { body } : {})
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}