-- Append-only risk comments and server-generated review history.
ALTER TABLE securescope_workspace_records DROP CONSTRAINT IF EXISTS securescope_workspace_records_kind_check;
ALTER TABLE securescope_workspace_records ADD CONSTRAINT securescope_workspace_records_kind_check CHECK (kind IN ('risk_group','risk_detail','risk_task','risk_snapshot','calendar_event','policy_comment','policy_audit','risk_comment','risk_review'));
