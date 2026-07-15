export interface BPCError {
  code: string;
  message: string;
  httpStatus: number;
}

export const BPC_ERRORS: Record<string, BPCError> = {
  missing_headers:       { code: 'missing_headers',       message: 'Required BPC headers missing',           httpStatus: 400 },
  invalid_signed_data:   { code: 'invalid_signed_data',   message: 'Cannot decode signed payload',           httpStatus: 400 },
  invalid_body_hash:     { code: 'invalid_body_hash',     message: 'Request body hash mismatch',             httpStatus: 400 },
  version_mismatch:      { code: 'version_mismatch',      message: 'Unsupported BPC protocol version',       httpStatus: 400 },
  method_path_mismatch:  { code: 'method_path_mismatch',  message: 'Method or path does not match payload',  httpStatus: 400 },
  pair_id_mismatch:      { code: 'pair_id_mismatch',      message: 'Pair ID does not match signed payload',  httpStatus: 400 },
  missing_body_hash:     { code: 'missing_body_hash',     message: 'Signed payload body hash is required',   httpStatus: 400 },
  unknown_pair:          { code: 'unknown_pair',          message: 'Pair ID not found',                      httpStatus: 401 },
  pair_revoked:          { code: 'pair_revoked',          message: 'Pair has been revoked',                  httpStatus: 401 },
  pair_locked:           { code: 'pair_locked',           message: 'Pair locked due to failed attempts',     httpStatus: 401 },
  pair_expired:          { code: 'pair_expired',          message: 'Pair has expired',                       httpStatus: 401 },
  pair_rotated:          { code: 'pair_rotated',          message: 'Pair has been rotated — use new pair',  httpStatus: 401 },
  shadow_denied:         { code: 'shadow_denied',         message: 'Request denied by anomaly policy',       httpStatus: 401 },
  ghost_pair_denied:     { code: 'ghost_pair_denied',     message: 'Canary credential denied',               httpStatus: 401 },
  invalid_signature:     { code: 'invalid_signature',     message: 'ECDSA signature verification failed',    httpStatus: 401 },
  replay_detected:       { code: 'replay_detected',       message: 'Nonce already seen — replay rejected',   httpStatus: 401 },
  timestamp_expired:     { code: 'timestamp_expired',     message: 'Request timestamp outside valid window', httpStatus: 401 },
  scope_violation:       { code: 'scope_violation',       message: 'Method not permitted for pair scope',    httpStatus: 403 },
  rate_limit_exceeded:   { code: 'rate_limit_exceeded',   message: 'Too many requests',                      httpStatus: 429 },
};
