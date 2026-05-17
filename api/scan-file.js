import formidable from 'formidable';
import fs from 'fs';
import FormData from 'form-data';

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
        // ✅ Parse the incoming multipart form
        const form = formidable({ maxFileSize: 32 * 1024 * 1024 });

        const [fields, files] = await new Promise((resolve, reject) => {
            form.parse(req, (err, fields, files) => {
                if (err) reject(err);
                else resolve([fields, files]);
            });
        });

        // ✅ formidable v3 returns arrays
        const file = Array.isArray(files.file) ? files.file[0] : files.file;
        if (!file) return res.status(400).json({ error: 'No file received' });

        // ✅ Build a FormData to forward to VirusTotal
        const formData = new FormData();
        formData.append('file', fs.createReadStream(file.filepath), {
            filename: file.originalFilename || 'upload',
            contentType: file.mimetype || 'application/octet-stream'
        });

        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': API_KEY,
                ...formData.getHeaders()
            },
            body: formData
        });

        const data = await response.json();
        res.status(response.status).json(data);

    } catch (error) {
        console.error('scan-file error:', error);
        res.status(500).json({ error: error.message });
    }
}
