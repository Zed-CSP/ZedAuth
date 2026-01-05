-- Track the previous refresh token hash to detect refresh token reuse.
ALTER TABLE sessions
    ADD COLUMN previous_refresh_token_hash VARCHAR(128) UNIQUE;

CREATE INDEX idx_sessions_prev_refresh_hash ON sessions(previous_refresh_token_hash);


