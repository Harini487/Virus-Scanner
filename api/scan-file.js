export const config = {
    api: {
        bodyParser: false
    }
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const API_KEY = process.env.VT_API_KEY;
    if (!API_KEY) return res.status(500).json({ error: 'API key not configured' });

    try {
        // Read raw body as buffer
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        const rawBody = Buffer.concat(chunks);

        // Get content-type header (includes boundary for multipart)
        const contentType = req.headers['content-type'];

        // Forward the raw multipart body directly to VirusTotal as-is
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': API_KEY,
                'content-type': contentType
            },
            body: rawBody
        });

        const data = await response.json();
        res.status(response.status).json(data);

    } catch (error) {
        console.error('scan-file error:', error);
        res.status(500).json({ error: error.message });
    }
}
