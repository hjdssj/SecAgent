export interface FollowupMessage {
  role: "user" | "assistant";
  content: string;
}

export interface AnalysisFollowupRequest {
  question: string;
  history: FollowupMessage[];
}

export interface AnalysisFollowupResponse {
  session_id: string;
  question: string;
  answer_markdown: string;
  llm_used: boolean;
  llm_model?: string | null;
  llm_provider?: string | null;
  llm_latency_ms: number;
  llm_prompt_tokens?: number | null;
  llm_completion_tokens?: number | null;
  llm_total_tokens?: number | null;
  llm_error?: string | null;
}
