import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";

const TOKENS_PATH = join(import.meta.dir, "..", "tokens.json");

async function main() {
  // Read hook input from stdin
  const stdinText = await Bun.stdin.text();
  let transcriptPath: string;

  try {
    const hookInput = JSON.parse(stdinText);
    transcriptPath = hookInput.transcript_path;
  } catch {
    console.error("Failed to parse stdin JSON");
    process.exit(1);
  }

  if (!transcriptPath || !existsSync(transcriptPath)) {
    console.error("Transcript not found:", transcriptPath);
    process.exit(1);
  }

  // Parse JSONL transcript for token usage
  const lines = readFileSync(transcriptPath, "utf-8").split("\n").filter(Boolean);
  let sessionInputTokens = 0;
  let sessionOutputTokens = 0;
  let sessionCacheReadTokens = 0;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      const usage = entry.message?.usage ?? entry.usage;
      if (usage) {
        sessionInputTokens += usage.input_tokens ?? 0;
        sessionOutputTokens += usage.output_tokens ?? 0;
        sessionCacheReadTokens += usage.cache_read_input_tokens ?? 0;
      }
    } catch {
      // skip unparseable lines
    }
  }

  const sessionTotal = sessionInputTokens + sessionOutputTokens + sessionCacheReadTokens;

  if (sessionTotal === 0) {
    console.log("No token usage found in transcript");
    return;
  }

  // Read existing tokens.json
  let tokensData: { total_tokens: number; sessions: any[] };
  try {
    tokensData = JSON.parse(readFileSync(TOKENS_PATH, "utf-8"));
  } catch {
    tokensData = { total_tokens: 0, sessions: [] };
  }

  // Append session and update total
  tokensData.sessions.push({
    date: new Date().toISOString(),
    input_tokens: sessionInputTokens,
    output_tokens: sessionOutputTokens,
    cache_read_tokens: sessionCacheReadTokens,
    total: sessionTotal,
  });
  tokensData.total_tokens += sessionTotal;

  writeFileSync(TOKENS_PATH, JSON.stringify(tokensData, null, 2) + "\n");
  console.log(`Tracked ${sessionTotal.toLocaleString()} tokens (total: ${tokensData.total_tokens.toLocaleString()})`);
}

main();
