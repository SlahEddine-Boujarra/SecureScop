-- Extend existing treatment vocabulary without changing or copying risk records.
ALTER TABLE securescope_risk_register
    DROP CONSTRAINT IF EXISTS securescope_risk_register_treatment_action_status_check;
ALTER TABLE securescope_risk_register
    ADD CONSTRAINT securescope_risk_register_treatment_action_status_check
    CHECK (treatment_action_status IN (
        'Not Started', 'In Progress', 'Completed', 'Blocked', 'Cancelled',
        'Rejected', 'Accepted risk'
    ));
