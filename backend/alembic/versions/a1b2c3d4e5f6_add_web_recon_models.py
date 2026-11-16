"""add_web_recon_models

Revision ID: a1b2c3d4e5f6
Revises: ff505bdc538b
Create Date: 2026-11-16 07:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'ff505bdc538b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'discovered_endpoints',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('scan_job_id', sa.Integer(), nullable=True),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('canonical_key', sa.String(length=64), nullable=False),
        sa.Column('scheme', sa.String(length=16), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('path', sa.Text(), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('query_params', sa.JSON(), nullable=False),
        sa.Column('has_params', sa.Boolean(), nullable=False),
        sa.Column('gf_categories', sa.JSON(), nullable=False),
        sa.Column('sources', sa.JSON(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_job_id'], ['scan_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_endpoint_org_canonical', 'discovered_endpoints', ['organization_id', 'canonical_key'], unique=False)
    op.create_index('ix_endpoint_org_host', 'discovered_endpoints', ['organization_id', 'host'], unique=False)
    op.create_index(op.f('ix_discovered_endpoints_has_params'), 'discovered_endpoints', ['has_params'], unique=False)
    op.create_index(op.f('ix_discovered_endpoints_organization_id'), 'discovered_endpoints', ['organization_id'], unique=False)

    op.create_table(
        'web_scan_executions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('scan_job_id', sa.Integer(), nullable=True),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.Column('tool_name', sa.String(length=64), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=False),
        sa.Column('items_processed', sa.Integer(), nullable=False),
        sa.Column('findings_count', sa.Integer(), nullable=False),
        sa.Column('parameters_used', sa.JSON(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_job_id'], ['scan_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_web_scan_executions_organization_id'), 'web_scan_executions', ['organization_id'], unique=False)
    op.create_index(op.f('ix_web_scan_executions_tool_name'), 'web_scan_executions', ['tool_name'], unique=False)

    op.create_table(
        'web_org_policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('interactsh_enabled', sa.Boolean(), nullable=False),
        sa.Column('interactsh_server', sa.String(length=255), nullable=True),
        sa.Column('interactsh_token_encrypted', sa.Text(), nullable=True),
        sa.Column('sqlmap_enabled', sa.Boolean(), nullable=False),
        sa.Column('nuclei_allow_intrusive', sa.Boolean(), nullable=False),
        sa.Column('max_concurrency', sa.Integer(), nullable=False),
        sa.Column('rate_limit_rps', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id'),
    )


def downgrade() -> None:
    op.drop_table('web_org_policies')
    op.drop_table('web_scan_executions')
    op.drop_table('discovered_endpoints')
