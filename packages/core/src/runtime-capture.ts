export interface AIRuntimeMetadata {
  capturedAt: string;
  source: 'env' | 'explicit' | 'combined';
  tool?: string;
  toolVersion?: string;
  model?: string;
  reasoning?: string;
  summaryMode?: string;
  directory?: string;
  cwd?: string;
  permissions?: string;
  agentsMd?: string;
  account?: string;
  email?: string;
  organization?: string;
  loginMethod?: string;
  collaborationMode?: string;
  sessionId?: string;
  sessionName?: string;
  contextWindow?: string;
  contextUsed?: string;
  contextLeft?: string;
  limits?: string;
  mcpServers?: string;
  settingSources?: string;
  statusText?: string;
  configText?: string;
  usageText?: string;
  statsText?: string;
  raw?: Record<string, unknown>;
}

export interface KeyGenerationCaptureEvent {
  protocol: 'bpc';
  packageName: string;
  event: string;
  generatedAt: string;
  keyFingerprint?: string;
  algorithm?: string;
  extractable?: boolean;
  runtime: AIRuntimeMetadata;
  details?: Record<string, unknown>;
}

export interface KeyGenerationCaptureOptions {
  runtimeMetadata?: Partial<AIRuntimeMetadata>;
  captureDetails?: Record<string, unknown>;
}

export type KeyGenerationCaptureSink = (
  event: KeyGenerationCaptureEvent,
) => void | Promise<void>;

type RuntimeProcess = {
  env?: Record<string, string | undefined>;
  cwd?: () => string;
  version?: string;
};

const REDACTED = '[REDACTED]';
const SENSITIVE_FIELD = /(?:secret|token|password|private|credential|api[_-]?key|shared[_-]?secret|raw[_-]?key|authorization)/i;

let captureSink: KeyGenerationCaptureSink | undefined;

export function setKeyGenerationCaptureSink(sink?: KeyGenerationCaptureSink): void {
  captureSink = sink;
}

export function collectRuntimeMetadata(
  overrides: Partial<AIRuntimeMetadata> = {},
): AIRuntimeMetadata {
  const runtimeProcess = getRuntimeProcess();
  const env = runtimeProcess?.env ?? {};
  const envMetadata: AIRuntimeMetadata = {
    capturedAt: new Date().toISOString(),
    source: 'env',
    tool: firstEnv(env, 'AI_RUNTIME_TOOL', 'CODEX_RUNTIME_TOOL', 'CLAUDE_RUNTIME_TOOL'),
    toolVersion: firstEnv(env, 'AI_RUNTIME_TOOL_VERSION', 'CODEX_VERSION', 'CLAUDE_CODE_VERSION')
      ?? runtimeProcess?.version,
    model: firstEnv(env, 'AI_RUNTIME_MODEL', 'CODEX_MODEL', 'CLAUDE_MODEL', 'ANTHROPIC_MODEL'),
    reasoning: firstEnv(env, 'AI_RUNTIME_REASONING', 'CODEX_REASONING', 'CLAUDE_REASONING'),
    summaryMode: firstEnv(env, 'AI_RUNTIME_SUMMARY_MODE', 'CODEX_SUMMARY_MODE', 'CLAUDE_SUMMARY_MODE'),
    directory: firstEnv(env, 'AI_RUNTIME_DIRECTORY', 'AI_RUNTIME_CWD', 'CODEX_CWD', 'CLAUDE_PROJECT_DIR'),
    cwd: firstEnv(env, 'AI_RUNTIME_CWD', 'CODEX_CWD', 'CLAUDE_PROJECT_DIR') ?? safeCwd(runtimeProcess),
    permissions: firstEnv(env, 'AI_RUNTIME_PERMISSIONS', 'CODEX_PERMISSIONS', 'CLAUDE_PERMISSIONS'),
    agentsMd: firstEnv(env, 'AI_RUNTIME_AGENTS_MD', 'CODEX_AGENTS_MD', 'CLAUDE_AGENTS_MD'),
    account: firstEnv(env, 'AI_RUNTIME_ACCOUNT', 'CODEX_ACCOUNT', 'CLAUDE_ACCOUNT'),
    email: firstEnv(env, 'AI_RUNTIME_EMAIL', 'CODEX_EMAIL', 'CLAUDE_EMAIL'),
    organization: firstEnv(env, 'AI_RUNTIME_ORGANIZATION', 'CODEX_ORGANIZATION', 'CLAUDE_ORGANIZATION'),
    loginMethod: firstEnv(env, 'AI_RUNTIME_LOGIN_METHOD', 'CODEX_LOGIN_METHOD', 'CLAUDE_LOGIN_METHOD'),
    collaborationMode: firstEnv(env, 'AI_RUNTIME_COLLABORATION_MODE', 'CODEX_COLLABORATION_MODE', 'CLAUDE_COLLABORATION_MODE'),
    sessionId: firstEnv(env, 'AI_RUNTIME_SESSION_ID', 'CODEX_SESSION_ID', 'CLAUDE_SESSION_ID'),
    sessionName: firstEnv(env, 'AI_RUNTIME_SESSION_NAME', 'CODEX_SESSION_NAME', 'CLAUDE_SESSION_NAME'),
    contextWindow: firstEnv(env, 'AI_RUNTIME_CONTEXT_WINDOW', 'CODEX_CONTEXT_WINDOW', 'CLAUDE_CONTEXT_WINDOW'),
    contextUsed: firstEnv(env, 'AI_RUNTIME_CONTEXT_USED', 'CODEX_CONTEXT_USED', 'CLAUDE_CONTEXT_USED'),
    contextLeft: firstEnv(env, 'AI_RUNTIME_CONTEXT_LEFT', 'CODEX_CONTEXT_LEFT', 'CLAUDE_CONTEXT_LEFT'),
    limits: firstEnv(env, 'AI_RUNTIME_LIMITS', 'CODEX_LIMITS', 'CLAUDE_LIMITS'),
    mcpServers: firstEnv(env, 'AI_RUNTIME_MCP_SERVERS', 'CODEX_MCP_SERVERS', 'CLAUDE_MCP_SERVERS'),
    settingSources: firstEnv(env, 'AI_RUNTIME_SETTING_SOURCES', 'CODEX_SETTING_SOURCES', 'CLAUDE_SETTING_SOURCES'),
    statusText: firstEnv(env, 'AI_RUNTIME_STATUS_TEXT', 'CODEX_STATUS_TEXT', 'CLAUDE_STATUS_TEXT'),
    configText: firstEnv(env, 'AI_RUNTIME_CONFIG_TEXT', 'CODEX_CONFIG_TEXT', 'CLAUDE_CONFIG_TEXT'),
    usageText: firstEnv(env, 'AI_RUNTIME_USAGE_TEXT', 'CODEX_USAGE_TEXT', 'CLAUDE_USAGE_TEXT'),
    statsText: firstEnv(env, 'AI_RUNTIME_STATS_TEXT', 'CODEX_STATS_TEXT', 'CLAUDE_STATS_TEXT'),
  };

  const hasOverrides = Object.keys(overrides).length > 0;
  return sanitizeCaptureValue({
    ...envMetadata,
    ...overrides,
    capturedAt: overrides.capturedAt ?? envMetadata.capturedAt,
    source: hasOverrides ? 'combined' : 'env',
  }) as AIRuntimeMetadata;
}

export function emitKeyGenerationCapture(
  event: Omit<KeyGenerationCaptureEvent, 'generatedAt' | 'runtime'> & {
    generatedAt?: string;
    runtime?: Partial<AIRuntimeMetadata>;
  },
): void {
  if (!captureSink) return;

  const sanitized = sanitizeCaptureValue({
    ...event,
    generatedAt: event.generatedAt ?? new Date().toISOString(),
    runtime: collectRuntimeMetadata(event.runtime ?? {}),
  }) as KeyGenerationCaptureEvent;

  try {
    const result = captureSink(sanitized);
    if (result && typeof (result as Promise<void>).catch === 'function') {
      (result as Promise<void>).catch(() => undefined);
    }
  } catch {
    // Capture is audit-only and must never break key generation.
  }
}

export function sanitizeCaptureValue(value: unknown, fieldName = ''): unknown {
  if (SENSITIVE_FIELD.test(fieldName)) return REDACTED;
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(item => sanitizeCaptureValue(item));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      out[key] = sanitizeCaptureValue(nested, key);
    }
    return out;
  }
  return value;
}

function firstEnv(env: Record<string, string | undefined>, ...names: string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (typeof value === 'string' && value.trim() !== '') return value;
  }
  return undefined;
}

function getRuntimeProcess(): RuntimeProcess | undefined {
  return (globalThis as unknown as { process?: RuntimeProcess }).process;
}

function safeCwd(runtimeProcess?: RuntimeProcess): string | undefined {
  try {
    return runtimeProcess?.cwd?.();
  } catch {
    return undefined;
  }
}
