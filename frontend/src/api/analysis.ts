import type { AnalysisFollowupRequest, AnalysisFollowupResponse } from "../types/analysis";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

async function parseError(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
  } catch {
    return `${response.status}`;
  }
}

export async function askAnalysisFollowup(
  sessionId: string,
  request: AnalysisFollowupRequest,
): Promise<AnalysisFollowupResponse> {
  const response = await fetch(`${API_BASE_URL}/api/analysis/${encodeURIComponent(sessionId)}/ask`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`Failed to ask follow-up question: ${await parseError(response)}`);
  }

  return response.json();
}

export interface FollowupStreamHandlers {
  onMeta?: (response: AnalysisFollowupResponse) => void;
  onChunk: (content: string) => void;
  onDone: (response: AnalysisFollowupResponse) => void;
}

export async function streamAnalysisFollowup(
  sessionId: string,
  request: AnalysisFollowupRequest,
  handlers: FollowupStreamHandlers,
): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/analysis/${encodeURIComponent(sessionId)}/ask/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`Failed to ask follow-up question: ${await parseError(response)}`);
  }

  if (!response.body) {
    throw new Error("Follow-up stream is not available in this browser");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();

    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    buffer = dispatchSseFrames(buffer, handlers);
  }

  buffer += decoder.decode();
  dispatchSseFrames(`${buffer}\n\n`, handlers);
}

function dispatchSseFrames(buffer: string, handlers: FollowupStreamHandlers): string {
  const frames = buffer.split("\n\n");
  const rest = frames.pop() ?? "";

  for (const frame of frames) {
    dispatchSseFrame(frame, handlers);
  }

  return rest;
}

function dispatchSseFrame(frame: string, handlers: FollowupStreamHandlers): void {
  const lines = frame.split(/\r?\n/);
  const event = lines
    .find((line) => line.startsWith("event:"))
    ?.slice("event:".length)
    .trim();
  const data = lines
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trim())
    .join("\n");

  if (!event || !data) {
    return;
  }

  const payload = JSON.parse(data);

  if (event === "meta") {
    handlers.onMeta?.(payload as AnalysisFollowupResponse);
    return;
  }

  if (event === "chunk") {
    handlers.onChunk(String(payload.content ?? ""));
    return;
  }

  if (event === "done") {
    handlers.onDone(payload as AnalysisFollowupResponse);
  }
}
