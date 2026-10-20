"""Canonicalize finding taxonomy labels.

Revision ID: 0022
Revises: 0021
"""
from __future__ import annotations

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE findings
        SET owasp_id = CASE
            WHEN owasp_id ~ '^API(10|[1-9])$'
                THEN owasp_id || chr(58) || '2023'
            WHEN owasp_id = 'INJ' THEN 'CWE-74'
            ELSE owasp_id
        END
        WHERE owasp_id ~ '^API(10|[1-9])$' OR owasp_id = 'INJ'
        """
    )
    op.execute(
        """
        UPDATE scan_runs
        SET findings_snapshot = COALESCE((
            SELECT jsonb_agg(
                CASE
                    WHEN item->>'owasp_id' ~ '^API(10|[1-9])$'
                        THEN jsonb_set(
                            item, '{owasp_id}',
                            to_jsonb((item->>'owasp_id') || chr(58) || '2023')
                        )
                    WHEN item->>'owasp_id' = 'INJ'
                        THEN jsonb_set(item, '{owasp_id}', '"CWE-74"'::jsonb)
                    ELSE item
                END
            )
            FROM jsonb_array_elements(findings_snapshot) AS item
        ), '[]'::jsonb)
        WHERE jsonb_typeof(findings_snapshot) = 'array'
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE scan_runs
        SET findings_snapshot = COALESCE((
            SELECT jsonb_agg(
                CASE
                    WHEN item->>'owasp_id' ~ (
                        '^API(10|[1-9])' || chr(58) || '2023$'
                    ) AND item->>'check' NOT IN (
                        'design_review', 'graphql_behavior',
                        'graphql_introspection', 'grpc_reflection',
                        'host_header', 'request_smuggling'
                    )
                        THEN jsonb_set(
                            item, '{owasp_id}',
                            to_jsonb(
                                replace(item->>'owasp_id', chr(58) || '2023', '')
                            )
                        )
                    WHEN item->>'owasp_id' = 'CWE-74'
                         AND item->>'check' IN (
                            'reflected_injection', 'signature_injection',
                            'oob_injection', 'xxe_confirmation'
                         ) THEN jsonb_set(item, '{owasp_id}', '"INJ"'::jsonb)
                    ELSE item
                END
            )
            FROM jsonb_array_elements(findings_snapshot) AS item
        ), '[]'::jsonb)
        WHERE jsonb_typeof(findings_snapshot) = 'array'
        """
    )
    op.execute(
        """
        UPDATE findings
        SET owasp_id = CASE
            WHEN owasp_id ~ ('^API(10|[1-9])' || chr(58) || '2023$')
                 AND "check" NOT IN (
                    'design_review', 'graphql_behavior',
                    'graphql_introspection', 'grpc_reflection',
                    'host_header', 'request_smuggling'
                 )
                THEN replace(owasp_id, chr(58) || '2023', '')
            WHEN owasp_id = 'CWE-74' AND "check" IN (
                'reflected_injection', 'signature_injection',
                'oob_injection', 'xxe_confirmation'
            ) THEN 'INJ'
            ELSE owasp_id
        END
        WHERE (
                owasp_id ~ ('^API(10|[1-9])' || chr(58) || '2023$')
                AND "check" NOT IN (
                    'design_review', 'graphql_behavior',
                    'graphql_introspection', 'grpc_reflection',
                    'host_header', 'request_smuggling'
                )
              )
           OR (owasp_id = 'CWE-74' AND "check" IN (
                'reflected_injection', 'signature_injection',
                'oob_injection', 'xxe_confirmation'
           ))
        """
    )
