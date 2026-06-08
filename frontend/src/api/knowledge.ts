import type {
  KnowledgeDocument,
  KnowledgeUploadRequest,
  KnowledgeUploadResponse,
} from "../types/knowledge";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

async function parseError(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
  } catch {
    return `${response.status}`;
  }
}

export async function fetchKnowledgeDocuments(): Promise<KnowledgeDocument[]> {
  const response = await fetch(`${API_BASE_URL}/api/knowledge/documents`);

  if (!response.ok) {
    throw new Error(`Failed to fetch knowledge documents: ${await parseError(response)}`);
  }

  return response.json();
}

export async function fetchKnowledgeDocument(source: string): Promise<KnowledgeDocument> {
  const response = await fetch(`${API_BASE_URL}/api/knowledge/documents/${encodeURIComponent(source)}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch knowledge document: ${await parseError(response)}`);
  }

  return response.json();
}

export async function saveKnowledgeDocument(
  request: KnowledgeUploadRequest,
): Promise<KnowledgeUploadResponse> {
  const response = await fetch(`${API_BASE_URL}/api/knowledge/documents`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`Failed to save knowledge document: ${await parseError(response)}`);
  }

  return response.json();
}

export async function uploadKnowledgeFile(
  file: File,
  overwrite: boolean,
): Promise<KnowledgeUploadResponse> {
  const body = new FormData();
  body.append("file", file);
  body.append("overwrite", String(overwrite));

  const response = await fetch(`${API_BASE_URL}/api/knowledge/documents/upload`, {
    method: "POST",
    body,
  });

  if (!response.ok) {
    throw new Error(`Failed to upload knowledge document: ${await parseError(response)}`);
  }

  return response.json();
}
