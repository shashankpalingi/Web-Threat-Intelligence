const API_BASE = 'http://localhost:8000';

export async function checkUrl(url) {
  const response = await fetch(`${API_BASE}/check?url=${encodeURIComponent(url)}`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('API request failed');
  return response.json();
}

export async function checkQrCode(decodedUrl, rawData = null) {
  const response = await fetch(`${API_BASE}/check-qr`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: decodedUrl, qr_data_raw: rawData || decodedUrl }),
  });
  if (!response.ok) throw new Error('QR scan API request failed');
  return response.json();
}

export async function getHistory(limit = 50, offset = 0, label = null) {
  let url = `${API_BASE}/history?limit=${limit}&offset=${offset}`;
  if (label) url += `&label=${label}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error('API request failed');
  return response.json();
}

export async function getStats() {
  const response = await fetch(`${API_BASE}/stats`);
  if (!response.ok) throw new Error('API request failed');
  return response.json();
}

export async function getModelInfo() {
  const response = await fetch(`${API_BASE}/model-info`);
  if (!response.ok) throw new Error('API request failed');
  return response.json();
}
