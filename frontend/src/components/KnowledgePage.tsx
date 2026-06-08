import { FileUp, RefreshCw, Save } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  fetchKnowledgeDocument,
  fetchKnowledgeDocuments,
  saveKnowledgeDocument,
  uploadKnowledgeFile,
} from "../api/knowledge";
import type { KnowledgeDocument, KnowledgeUploadResponse } from "../types/knowledge";
import { ReportPanel } from "./ReportPanel";

export function KnowledgePage() {
  const [documents, setDocuments] = useState<KnowledgeDocument[]>([]);
  const [selectedSource, setSelectedSource] = useState<string | null>(null);
  const [selectedDocument, setSelectedDocument] = useState<KnowledgeDocument | null>(null);
  const [filename, setFilename] = useState("custom_knowledge.md");
  const [content, setContent] = useState("# Custom Knowledge\n\n## Detection Notes\n\n");
  const [overwrite, setOverwrite] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<KnowledgeUploadResponse | null>(null);

  const selectedSummary = useMemo(() => {
    if (!selectedDocument) {
      return "No document selected";
    }

    return `${selectedDocument.category} / ${selectedDocument.tags.length} tags`;
  }, [selectedDocument]);

  const loadDocuments = useCallback(async () => {
    setIsLoading(true);
    try {
      const nextDocuments = await fetchKnowledgeDocuments();
      setDocuments(nextDocuments);
      setError(null);
      setSelectedSource((current) => {
        if (current && nextDocuments.some((document) => document.source === current)) {
          return current;
        }

        return nextDocuments[0]?.source ?? null;
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to fetch knowledge documents");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDocuments();
  }, [loadDocuments]);

  useEffect(() => {
    if (!selectedSource) {
      setSelectedDocument(null);
      return;
    }

    void fetchKnowledgeDocument(selectedSource)
      .then((document) => {
        setSelectedDocument(document);
        setError(null);
      })
      .catch((caught) => {
        setSelectedDocument(null);
        setError(caught instanceof Error ? caught.message : "Failed to fetch knowledge document");
      });
  }, [selectedSource]);

  const handleSave = useCallback(async () => {
    setIsSaving(true);
    try {
      const uploadResult = await saveKnowledgeDocument({
        filename,
        content,
        overwrite,
      });
      setResult(uploadResult);
      setError(null);
      await loadDocuments();
      setSelectedSource(uploadResult.source);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to save knowledge document");
    } finally {
      setIsSaving(false);
    }
  }, [content, filename, loadDocuments, overwrite]);

  const handleFileUpload = useCallback(
    async (file: File | null) => {
      if (!file) {
        return;
      }

      setIsSaving(true);
      try {
        const uploadResult = await uploadKnowledgeFile(file, overwrite);
        setResult(uploadResult);
        setError(null);
        await loadDocuments();
        setSelectedSource(uploadResult.source);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Failed to upload knowledge document");
      } finally {
        setIsSaving(false);
      }
    },
    [loadDocuments, overwrite],
  );

  return (
    <div className="knowledge-layout">
      <section className="knowledge-panel">
        <div className="panel-heading">
          <h2>Knowledge Documents</h2>
          <button
            className="icon-button icon-button--quiet"
            type="button"
            title="Refresh documents"
            onClick={() => void loadDocuments()}
            disabled={isLoading}
          >
            <RefreshCw size={16} className={isLoading ? "is-spinning" : ""} aria-hidden="true" />
          </button>
        </div>
        <div className="knowledge-list">
          {documents.map((document) => (
            <button
              className={document.source === selectedSource ? "knowledge-row is-selected" : "knowledge-row"}
              type="button"
              key={document.source}
              onClick={() => setSelectedSource(document.source)}
            >
              <strong>{document.title}</strong>
              <span>{document.source}</span>
              <span className="status-pill">{document.category}</span>
            </button>
          ))}
          {documents.length === 0 ? <p className="knowledge-empty">No documents</p> : null}
        </div>
      </section>

      <section className="knowledge-panel">
        <div className="panel-heading">
          <h2>Upload</h2>
          <span>{result ? result.source : "Markdown"}</span>
        </div>
        <div className="knowledge-form">
          {error ? <span className="status status--error">{error}</span> : null}
          {result ? <span className="status status--success">{result.message}</span> : null}
          <label>
            <span className="metric__label">Filename</span>
            <input value={filename} onChange={(event) => setFilename(event.target.value)} />
          </label>
          <label className="checkbox-control">
            <input
              type="checkbox"
              checked={overwrite}
              onChange={(event) => setOverwrite(event.target.checked)}
            />
            <span>Overwrite existing</span>
          </label>
          <label>
            <span className="metric__label">File</span>
            <input
              type="file"
              accept=".md,text/markdown,text/plain"
              onChange={(event) => {
                const file = event.currentTarget.files?.[0] ?? null;
                void handleFileUpload(file);
                event.currentTarget.value = "";
              }}
            />
          </label>
          <label className="knowledge-editor">
            <span className="metric__label">Markdown</span>
            <textarea value={content} onChange={(event) => setContent(event.target.value)} rows={12} />
          </label>
          <button className="primary-button" type="button" onClick={() => void handleSave()} disabled={isSaving}>
            {isSaving ? <RefreshCw size={16} className="is-spinning" aria-hidden="true" /> : <Save size={16} />}
            {isSaving ? "Saving" : "Save"}
          </button>
        </div>
      </section>

      <section className="knowledge-detail">
        <div className="detail-header">
          <div>
            <span className="eyebrow mono">{selectedDocument?.source ?? "knowledge"}</span>
            <h1>{selectedDocument?.title ?? "Knowledge"}</h1>
          </div>
          <span className="status-pill">{selectedSummary}</span>
        </div>
        {selectedDocument ? (
          <>
            <div className="chip-row">
              {selectedDocument.tags.map((tag) => (
                <span className="chip" key={`${selectedDocument.source}-${tag}`}>
                  {tag}
                </span>
              ))}
              {selectedDocument.tags.length === 0 ? <span className="muted">No tags</span> : null}
            </div>
            <ReportPanel markdown={selectedDocument.content} />
          </>
        ) : (
          <section className="detail-empty">
            <FileUp size={24} aria-hidden="true" />
            <span>No document selected</span>
          </section>
        )}
      </section>
    </div>
  );
}
