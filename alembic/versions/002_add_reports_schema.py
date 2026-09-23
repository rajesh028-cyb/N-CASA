"""Add reports table schema

Revision ID: 002_add_reports_schema
Revises: 001_initial_ncasa_schema
Create Date: 2026-09-23 09:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_add_reports_schema'
down_revision: Union[str, None] = '001_initial_ncasa_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('report_id', sa.String(length=128), nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('report_version', sa.String(length=32), nullable=False, server_default='1.0'),
        sa.Column('html_path', sa.String(length=512), nullable=False),
        sa.Column('pdf_path', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_reports_id', 'reports', ['id'], unique=False)
    op.create_index('ix_reports_report_id', 'reports', ['report_id'], unique=True)
    op.create_index('ix_reports_audit_id', 'reports', ['audit_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_reports_audit_id', table_name='reports')
    op.drop_index('ix_reports_report_id', table_name='reports')
    op.drop_index('ix_reports_id', table_name='reports')
    op.drop_table('reports')
