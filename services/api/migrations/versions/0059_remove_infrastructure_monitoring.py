"""Remove retired infrastructure monitoring storage.

Revision ID: 0059
Revises: 0058

Applying this migration deletes monitoring/source data. Scan data is retained.
Downgrade restores empty tables, not deleted monitoring records or subscriptions.
"""
from __future__ import annotations

from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Retired events must never be retried after their producer is removed.
    op.execute("""
        UPDATE notification_deliveries
        SET state = 'dead', last_error = 'feature_removed'
        WHERE event_type IN ('monitor.alert', 'monitor.recovered')
          AND state IN ('pending', 'delivering', 'failed')
    """)
    op.execute("""
        UPDATE notification_endpoints
        SET events = COALESCE((
            SELECT jsonb_agg(event)
            FROM jsonb_array_elements(events) AS event
            WHERE event #>> '{}' NOT IN ('monitor.alert', 'monitor.recovered')
        ), '[]'::jsonb)
        WHERE events ?| array['monitor.alert', 'monitor.recovered']
    """)
    for table in (
        "monitoring_alerts", "monitoring_rapid_runs", "monitoring_runs",
        "infrastructure_monitors", "evidence_audit", "evidence_sources",
    ):
        op.drop_table(table)


def downgrade() -> None:
    # Frozen PostgreSQL DDL: no imports from the removed application models.
    op.execute("""
        CREATE TABLE evidence_sources (
            id UUID NOT NULL,
            tenant_id VARCHAR(120) NOT NULL,
            name VARCHAR(160) NOT NULL,
            target_binding VARCHAR(2048) NOT NULL,
            connector VARCHAR(32) NOT NULL,
            config JSONB DEFAULT '{}' NOT NULL,
            secret_ref TEXT,
            error_code VARCHAR(40),
            watermark DATE,
            revision INTEGER DEFAULT '1' NOT NULL,
            status VARCHAR(20) DEFAULT 'ready' NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id)
        )
    """)
    op.execute("""
        CREATE INDEX ix_evidence_sources_tenant_id ON evidence_sources (tenant_id)
    """)
    op.execute("""
        CREATE TABLE evidence_audit (
            id UUID NOT NULL,
            tenant_id VARCHAR(120) NOT NULL,
            source_id UUID NOT NULL,
            action VARCHAR(32) NOT NULL,
            outcome VARCHAR(40) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(source_id) REFERENCES evidence_sources (id) ON DELETE CASCADE
        )
    """)
    op.execute("""
        CREATE INDEX ix_evidence_audit_tenant_id ON evidence_audit (tenant_id)
    """)
    op.execute("""
        CREATE TABLE infrastructure_monitors (
            id UUID NOT NULL,
            tenant_id VARCHAR(120) NOT NULL,
            name VARCHAR(160) NOT NULL,
            target_binding VARCHAR(2048) NOT NULL,
            source_ids JSONB DEFAULT '[]' NOT NULL,
            schedule_minutes INTEGER DEFAULT '1440' NOT NULL,
            minimum_baseline_days INTEGER DEFAULT '7' NOT NULL,
            status VARCHAR(20) DEFAULT 'active' NOT NULL,
            scan_id UUID,
            schedule_enabled BOOLEAN DEFAULT 'false' NOT NULL,
            rapid_enabled BOOLEAN DEFAULT 'false' NOT NULL,
            retention_days INTEGER DEFAULT '90' NOT NULL,
            context JSONB DEFAULT '{}' NOT NULL,
            triage JSONB DEFAULT '{}' NOT NULL,
            ai_briefing JSONB DEFAULT '{}' NOT NULL,
            last_observation_date DATE,
            last_run_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT fk_monitor_scan FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE SET NULL
        )
    """)
    op.execute("""
        CREATE INDEX ix_infrastructure_monitors_tenant_id
            ON infrastructure_monitors (tenant_id)
    """)
    op.execute("""
        CREATE TABLE monitoring_alerts (
            id UUID NOT NULL,
            monitor_id UUID NOT NULL,
            observation_date DATE NOT NULL,
            state VARCHAR(24) NOT NULL,
            acknowledged BOOLEAN DEFAULT 'false' NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(monitor_id) REFERENCES infrastructure_monitors (id) ON DELETE CASCADE
        )
    """)
    op.execute("""
        CREATE INDEX ix_monitoring_alerts_monitor_id ON monitoring_alerts (monitor_id)
    """)
    op.execute("""
        CREATE TABLE monitoring_rapid_runs (
            id UUID NOT NULL,
            monitor_id UUID NOT NULL,
            window_start TIMESTAMP WITH TIME ZONE NOT NULL,
            window_end TIMESTAMP WITH TIME ZONE NOT NULL,
            observations JSONB DEFAULT '[]' NOT NULL,
            skipped JSONB DEFAULT '{}' NOT NULL,
            pulse JSONB DEFAULT '{}' NOT NULL,
            waf_count INTEGER DEFAULT '0' NOT NULL,
            application_count INTEGER DEFAULT '0' NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT uq_monitoring_rapid_window UNIQUE (monitor_id, window_start, window_end),
            FOREIGN KEY(monitor_id) REFERENCES infrastructure_monitors (id) ON DELETE CASCADE
        )
    """)
    op.execute("""
        CREATE INDEX ix_monitoring_rapid_runs_monitor_id ON monitoring_rapid_runs (monitor_id)
    """)
    op.execute("""
        CREATE TABLE monitoring_runs (
            id UUID NOT NULL,
            monitor_id UUID NOT NULL,
            observation_date DATE NOT NULL,
            status VARCHAR(20) DEFAULT 'queued' NOT NULL,
            state VARCHAR(24) DEFAULT 'no_data' NOT NULL,
            error_code VARCHAR(40),
            claim UUID,
            scope_revision VARCHAR(64) DEFAULT '' NOT NULL,
            correlations JSONB DEFAULT '[]' NOT NULL,
            baseline_start DATE,
            baseline_end DATE,
            baseline_days_available INTEGER DEFAULT '0' NOT NULL,
            data_quality VARCHAR(20) DEFAULT 'unknown' NOT NULL,
            source_revisions JSONB DEFAULT '{}' NOT NULL,
            metrics JSONB DEFAULT '{}' NOT NULL,
            observations JSONB DEFAULT '[]' NOT NULL,
            started_at TIMESTAMP WITH TIME ZONE,
            finished_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT uq_monitoring_run_day UNIQUE (monitor_id, observation_date),
            FOREIGN KEY(monitor_id) REFERENCES infrastructure_monitors (id) ON DELETE CASCADE
        )
    """)
    op.execute("""
        CREATE INDEX ix_monitoring_runs_monitor_id ON monitoring_runs (monitor_id)
    """)
