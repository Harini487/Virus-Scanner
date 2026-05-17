import formidable from 'formidable';
import fs from 'fs';
import FormData from 'form-data';

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const API_KEY = process.env.VT_API_KEY;
    if (!API_KEY) return res.status(500).json({ error: 'API key not configured' });

    const form = formidable({ maxFileSize: 32 * 1024 * 1024 });

    form.parse(req, async (err, fields, files) => {
        if (err) return res.status(500).json({ error: 'File parse error' });

        const file = files.file?.[0];
        if (!file) return res.status(400).json({ error: 'No file provided' });

        try {
            const formData = new FormData();
            formData.append('file', fs.createReadStream(file.filepath), file.originalFilename);

            const response = await fetch('https://www.virustotal.com/api/v3/files', {
                method: 'POST',
                headers: {
                    "x-apikey": API_KEY,
                    ...formData.getHeaders()
                },
                body: formData
            });

            const data = await response.json();
            res.status(response.status).json(data);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });
}
