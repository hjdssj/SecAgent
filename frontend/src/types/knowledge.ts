export interface KnowledgeDocument {
  doc_id: string;
  title: string;
  category: string;
  source: string;
  tags: string[];
  content: string;
}

export interface KnowledgeUploadRequest {
  filename: string;
  content: string;
  overwrite: boolean;
}

export interface KnowledgeUploadResponse {
  source: string;
  doc_id: string;
  title: string;
  category: string;
  tags: string[];
  chunk_count: number;
  overwritten: boolean;
  message: string;
}
