"""Initial N-CASA Schema

Revision ID: 001_initial_ncasa_schema
Revises: 
Create Date: 2026-09-22 19:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_ncasa_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # audits table
    op.create_table(
        'audits',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=64), nullable=False),
        sa.Column('compliance_framework', sa.String(length=64), nullable=False, server_default='CIS'),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('stored_path', sa.String(length=512), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('inventory', sa.JSON(), nullable=True),
        sa.Column('detection_summary', sa.JSON(), nullable=True),
        sa.Column('ai_summary', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audits_audit_id', 'audits', ['audit_id'], unique=True)
    op.create_index('ix_audits_status', 'audits', ['status'], unique=False)
    op.create_index('ix_audits_created_at', 'audits', ['created_at'], unique=False)

    # audit_config_files table
    op.create_table(
        'audit_config_files',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('relative_path', sa.String(length=512), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('line_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('char_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('non_empty_line_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('comment_line_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('candidate_hostname', sa.String(length=255), nullable=True),
        sa.Column('encoding', sa.String(length=64), nullable=False, server_default='utf-8'),
        sa.Column('status', sa.String(length=64), nullable=False, server_default='DISCOVERED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_config_files_file_id', 'audit_config_files', ['file_id'], unique=False)
    op.create_index('ix_audit_config_files_audit_id', 'audit_config_files', ['audit_id'], unique=False)
    op.create_index('ix_audit_config_files_sha256', 'audit_config_files', ['sha256'], unique=False)

    # vendor_detections table
    op.create_table(
        'vendor_detections',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('device_type', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('method', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=64), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vendor_detections_audit_id', 'vendor_detections', ['audit_id'], unique=False)
    op.create_index('ix_vendor_detections_file_id', 'vendor_detections', ['file_id'], unique=False)
    op.create_index('ix_vendor_detections_vendor', 'vendor_detections', ['vendor'], unique=False)

    # parsed_configurations table
    op.create_table(
        'parsed_configurations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=64), nullable=False),
        sa.Column('parsed_data', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_parsed_configurations_audit_id', 'parsed_configurations', ['audit_id'], unique=False)
    op.create_index('ix_parsed_configurations_file_id', 'parsed_configurations', ['file_id'], unique=False)

    # normalized_configurations table
    op.create_table(
        'normalized_configurations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('normalization_method', sa.String(length=64), nullable=False, server_default='DETERMINISTIC'),
        sa.Column('requires_manual_validation', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('normalized_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_normalized_configurations_audit_id', 'normalized_configurations', ['audit_id'], unique=False)
    op.create_index('ix_normalized_configurations_file_id', 'normalized_configurations', ['file_id'], unique=False)

    # compliance_results table
    op.create_table(
        'compliance_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('expected', sa.String(length=512), nullable=False),
        sa.Column('observed', sa.String(length=512), nullable=False),
        sa.Column('rationale', sa.String(length=1024), nullable=False),
        sa.Column('internal_mapping', sa.String(length=64), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('audit_id', 'control_id', name='uq_audit_control')
    )
    op.create_index('ix_compliance_results_audit_id', 'compliance_results', ['audit_id'], unique=False)
    op.create_index('ix_compliance_results_control_id', 'compliance_results', ['control_id'], unique=False)
    op.create_index('ix_compliance_results_severity', 'compliance_results', ['severity'], unique=False)
    op.create_index('ix_compliance_results_status', 'compliance_results', ['status'], unique=False)

    # findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=2048), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('expected', sa.String(length=512), nullable=False),
        sa.Column('observed', sa.String(length=512), nullable=False),
        sa.Column('rationale', sa.String(length=1024), nullable=False),
        sa.Column('remediation_status', sa.String(length=64), nullable=False, server_default='NOT_REMEDIATED'),
        sa.Column('affected_files', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('audit_id', 'finding_id', name='uq_audit_finding')
    )
    op.create_index('ix_findings_audit_id', 'findings', ['audit_id'], unique=False)
    op.create_index('ix_findings_finding_id', 'findings', ['finding_id'], unique=False)
    op.create_index('ix_findings_control_id', 'findings', ['control_id'], unique=False)
    op.create_index('ix_findings_severity', 'findings', ['severity'], unique=False)

    # assessment_limitations table
    op.create_table(
        'assessment_limitations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=2048), nullable=False),
        sa.Column('affected_files', sa.JSON(), nullable=True),
        sa.Column('reason', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_assessment_limitations_audit_id', 'assessment_limitations', ['audit_id'], unique=False)

    # remediations table
    op.create_table(
        'remediations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('remediation_id', sa.String(length=64), nullable=False),
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('device_type', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=2048), nullable=False),
        sa.Column('status', sa.String(length=64), nullable=False, server_default='PROPOSED'),
        sa.Column('review_status', sa.String(length=64), nullable=False, server_default='PENDING'),
        sa.Column('proposed_commands', sa.JSON(), nullable=True),
        sa.Column('current_configuration', sa.JSON(), nullable=True),
        sa.Column('proposed_configuration', sa.JSON(), nullable=True),
        sa.Column('validation_steps', sa.JSON(), nullable=True),
        sa.Column('rollback_guidance', sa.JSON(), nullable=True),
        sa.Column('affected_files', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('manual_review_required', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('required_inputs', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('audit_id', 'remediation_id', name='uq_audit_remediation')
    )
    op.create_index('ix_remediations_audit_id', 'remediations', ['audit_id'], unique=False)
    op.create_index('ix_remediations_remediation_id', 'remediations', ['remediation_id'], unique=False)
    op.create_index('ix_remediations_finding_id', 'remediations', ['finding_id'], unique=False)

    # ai_analysis_results table
    op.create_table(
        'ai_analysis_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('analysis_method', sa.String(length=64), nullable=False),
        sa.Column('vendor_hypothesis', sa.String(length=64), nullable=False),
        sa.Column('device_type', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('normalized_output', sa.JSON(), nullable=True),
        sa.Column('requires_manual_validation', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ai_analysis_results_audit_id', 'ai_analysis_results', ['audit_id'], unique=False)
    op.create_index('ix_ai_analysis_results_file_id', 'ai_analysis_results', ['file_id'], unique=False)

    # ai_explanations table
    op.create_table(
        'ai_explanations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('summary', sa.String(length=1024), nullable=False),
        sa.Column('security_impact', sa.String(length=2048), nullable=False),
        sa.Column('evidence_interpretation', sa.String(length=2048), nullable=False),
        sa.Column('recommended_review', sa.String(length=2048), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.audit_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ai_explanations_audit_id', 'ai_explanations', ['audit_id'], unique=False)
    op.create_index('ix_ai_explanations_finding_id', 'ai_explanations', ['finding_id'], unique=False)


def downgrade() -> None:
    op.drop_table('ai_explanations')
    op.drop_table('ai_analysis_results')
    op.drop_table('remediations')
    op.drop_table('assessment_limitations')
    op.drop_table('findings')
    op.drop_table('compliance_results')
    op.drop_table('normalized_configurations')
    op.drop_table('parsed_configurations')
    op.drop_table('vendor_detections')
    op.drop_table('audit_config_files')
    op.drop_table('audits')
