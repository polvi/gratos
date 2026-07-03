-- Sandboxes minted with a valid session are owned: user_id records the owner
-- (a user in the minting tenant's pool, e.g. authgravity.org for the dash).
-- Owned sandboxes persist until deleted from the dashboard; anonymous ones
-- (user_id NULL) keep the 7-day sweep via AuthRPC.sweepSandboxes.
ALTER TABLE sandboxes ADD COLUMN user_id TEXT;
CREATE INDEX idx_sandboxes_user_id ON sandboxes(user_id);
