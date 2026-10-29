// Jev through OpenRouter's decisions endpoint, for the benchmark only (the extension goes through
// Pi's model registry). The key comes from OPENROUTER_API_KEY and is never printed or written.
export const MODEL = "typesafe/jev-1.14";

export interface JevResult {
	answers?: Record<string, number>;
	error?: string;
	ms: number;
	inputTokens?: number;
	cost?: number;
}

export async function jev(state: Record<string, unknown>, questions: Record<string, object>, timeoutMs = 8000, model = MODEL): Promise<JevResult> {
	const key = process.env.OPENROUTER_API_KEY;
	if (!key) return { error: "set OPENROUTER_API_KEY", ms: 0 };
	const deadline = AbortSignal.timeout(timeoutMs);
	const started = performance.now();
	const ms = () => Math.round(performance.now() - started);
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			const res = await fetch("https://openrouter.ai/api/alpha/decisions", {
				method: "POST",
				headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
				body: JSON.stringify({ model, state, questions }),
				signal: deadline,
				redirect: "error",
			});
			const body = (await res.json().catch(() => undefined)) as Record<string, any> | undefined;
			if (res.status === 429 || res.status >= 500) {
				if (deadline.aborted) break;
				await new Promise((r) => setTimeout(r, Math.min(1500 * (attempt + 1), timeoutMs / 4)));
				continue;
			}
			if (!res.ok) return { error: `HTTP ${res.status} ${String(body?.error?.message ?? "").slice(0, 120)}`, ms: ms() };
			const answers: Record<string, number> = {};
			for (const [id, a] of Object.entries(body?.answers ?? {})) {
				const p = (a as any)?.noul ?? (a as any)?.probability;
				if (typeof p === "number" && p >= 0 && p <= 1) answers[id] = p;
			}
			if (Object.keys(answers).length !== Object.keys(questions).length) return { error: "invalid response", ms: ms() };
			return { answers, ms: ms(), inputTokens: body?.usage?.input_tokens ?? body?.usage?.prompt_tokens, cost: body?.usage?.cost };
		} catch (e) {
			if ((e as Error).name === "TimeoutError" || deadline.aborted) return { error: `timeout ${timeoutMs} ms`, ms: ms() };
			if (attempt === 2) return { error: String((e as Error).message).slice(0, 120), ms: ms() };
		}
	}
	return { error: "rate limited", ms: ms() };
}
