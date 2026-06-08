import { MessageSquareText, RefreshCw, SendHorizonal } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { streamAnalysisFollowup } from "../api/analysis";
import type { FollowupMessage } from "../types/analysis";

interface ChatTurn {
  id: string;
  question: string;
  answer: string;
  llmUsed: boolean;
  llmError?: string | null;
  latencyMs: number;
  isStreaming?: boolean;
}

interface FollowupChatProps {
  sessionId?: string | null;
}

export function FollowupChat({ sessionId }: FollowupChatProps) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [isAsking, setIsAsking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setQuestion("");
    setTurns([]);
    setError(null);
  }, [sessionId]);

  const history = useMemo<FollowupMessage[]>(
    () =>
      turns.flatMap((turn) => [
        { role: "user", content: turn.question },
        { role: "assistant", content: turn.answer },
      ]),
    [turns],
  );

  async function handleAsk(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!sessionId || !question.trim()) {
      return;
    }

    const nextQuestion = question.trim();
    const turnId = `${Date.now()}-${turns.length}`;
    setQuestion("");
    setIsAsking(true);
    setTurns((current) => [
      ...current,
      {
        id: turnId,
        question: nextQuestion,
        answer: "",
        llmUsed: false,
        latencyMs: 0,
        isStreaming: true,
      },
    ]);

    try {
      await streamAnalysisFollowup(
        sessionId,
        {
          question: nextQuestion,
          history: history.slice(-12),
        },
        {
          onMeta: (response) => {
            setTurns((current) =>
              current.map((turn) =>
                turn.id === turnId
                  ? {
                      ...turn,
                      question: response.question,
                      llmUsed: response.llm_used,
                      llmError: response.llm_error,
                      latencyMs: response.llm_latency_ms,
                    }
                  : turn,
              ),
            );
          },
          onChunk: (content) => {
            setTurns((current) =>
              current.map((turn) =>
                turn.id === turnId
                  ? {
                      ...turn,
                      answer: `${turn.answer}${content}`,
                    }
                  : turn,
              ),
            );
          },
          onDone: (response) => {
            setTurns((current) =>
              current.map((turn) =>
                turn.id === turnId
                  ? {
                      ...turn,
                      question: response.question,
                      answer: response.answer_markdown,
                      llmUsed: response.llm_used,
                      llmError: response.llm_error,
                      latencyMs: response.llm_latency_ms,
                      isStreaming: false,
                    }
                  : turn,
              ),
            );
          },
        },
      );
      setError(null);
    } catch (caught) {
      setTurns((current) => current.filter((turn) => turn.id !== turnId));
      setError(caught instanceof Error ? caught.message : "Failed to ask follow-up question");
      setQuestion(nextQuestion);
    } finally {
      setIsAsking(false);
    }
  }

  return (
    <section className="followup-panel">
      <div className="panel-heading">
        <h2>
          <span aria-hidden="true">
            <MessageSquareText size={17} />
          </span>
          多轮追问
        </h2>
        <span>{sessionId ? "Analysis Session" : "No Session"}</span>
      </div>

      <div className="followup-body">
        {!sessionId ? (
          <p className="muted">这条告警没有保存的分析会话，暂时不能追问。</p>
        ) : turns.length > 0 ? (
          <div className="followup-thread" aria-live="polite">
            {turns.map((turn) => (
              <article className="followup-turn" key={turn.id}>
                <div className="followup-bubble followup-bubble--user">
                  <span className="metric__label">Question</span>
                  <p>{turn.question}</p>
                </div>
                <div className="followup-bubble followup-bubble--assistant">
                  <span className="metric__label">
                    Answer · {turn.isStreaming ? "Streaming" : turn.llmUsed ? "LLM" : turn.llmError ?? "Fallback"} ·{" "}
                    {turn.latencyMs}ms
                  </span>
                  <div className="markdown-body markdown-body--compact">
                    {turn.answer ? (
                      <ReactMarkdown>{turn.answer}</ReactMarkdown>
                    ) : (
                      <p className="streaming-placeholder">正在生成...</p>
                    )}
                  </div>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="muted">围绕这条告警的分析上下文继续提问。</p>
        )}

        {error ? <span className="status status--error">{error}</span> : null}

        <form className="followup-form" onSubmit={handleAsk}>
          <textarea
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="例如：为什么这个告警需要人工复核？"
            rows={3}
            disabled={!sessionId || isAsking}
          />
          <button className="primary-button" type="submit" disabled={!sessionId || isAsking || !question.trim()}>
            {isAsking ? <RefreshCw size={16} className="is-spinning" aria-hidden="true" /> : <SendHorizonal size={16} />}
            {isAsking ? "生成中" : "发送"}
          </button>
        </form>
      </div>
    </section>
  );
}
