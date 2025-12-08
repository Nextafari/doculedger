"""
Serializers for doculedger - implementing the sequence diagram flows using ONLY existing models.

Covers:
- Upload & Registration Flow (F1, F2, F3) - using Document, BlockchainTransaction, AuditEvent
- Integrity Verification Flow (F4) - using Document, AuditEvent
- Role-Based Approval Flow (F5) - using ApprovalRequest, ApprovalRecord, Role
- Audit logging (F6) - using AuditEvent
"""

from rest_framework import serializers
from django.utils import timezone

from .models import (
    User,
    Role,
    Project,
    Document,
    ApprovalRequest,
    ApprovalRecord,
    BlockchainTransaction,
    AuditEvent,
    Activity,
    Notification,
    EncryptionMetadata,
)


# =============================================================================
# User & Project Serializers
# =============================================================================


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "mobile",
            "is_active",
            "created_at",
        ]
        read_only_fields = ["id", "created_at", "is_active"]


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Role model"""

    class Meta:
        model = Role
        fields = ["id", "name", "description"]
        read_only_fields = ["id"]


class ProjectSerializer(serializers.ModelSerializer):
    """Serializer for Project model"""

    class Meta:
        model = Project
        fields = ["id", "name", "description", "created_at"]
        read_only_fields = ["id", "created_at"]


# =============================================================================
# Upload & Registration Serializers
# =============================================================================


class DocumentUploadSerializer(serializers.Serializer):
    """
    Input serializer for uploading documents (Step 1 in sequence diagram).
    Maps to: UI -> DocSvc -> uploadFile(file)
    """

    project_id = serializers.UUIDField()
    file = serializers.FileField()
    original_filename = serializers.CharField(max_length=512)


class DocumentSerializer(serializers.ModelSerializer):
    """
    Serializer for Document model.
    Includes computed fields for related data.
    """

    uploader_email = serializers.EmailField(source="uploader.email", read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Document
        fields = [
            "id",
            "project",
            "project_name",
            "uploader",
            "uploader_email",
            "original_filename",
            "s3_url",
            "cid",
            "sha256_hash",
            "status",
            "uploaded_at",
            "updated_at",
        ]
        read_only_fields = ["id", "uploaded_at", "updated_at", "cid", "sha256_hash"]


class BlockchainTransactionSerializer(serializers.ModelSerializer):
    """
    Serializer for blockchain transaction records.
    Maps to: metaTx.register, metaTx.approve.A, metaTx.approve.B in sequence diagram
    """

    class Meta:
        model = BlockchainTransaction
        fields = [
            "id",
            "tx_hash",
            "block_number",
            "status",
            "confirmations",
            "created_at",
            "confirmed_at",
            "gas_fee",
        ]
        read_only_fields = ["id", "created_at"]


# =============================================================================
# Integrity Verification Serializers
# =============================================================================


class VerifyDocumentSerializer(serializers.Serializer):
    """
    Input serializer for document verification.
    Maps to: verify(docId) in sequence diagram
    """

    document_id = serializers.UUIDField()


class VerificationResultSerializer(serializers.Serializer):
    """
    Output serializer for verification results.
    Maps to: result(valid, evidence) + proof in sequence diagram
    """

    document_id = serializers.UUIDField()
    is_valid = serializers.BooleanField()
    stored_hash = serializers.CharField()
    computed_hash = serializers.CharField()
    cid = serializers.CharField()
    proof = serializers.JSONField()
    verified_at = serializers.DateTimeField()
    message = serializers.CharField()


# =============================================================================
# Role-Based Approval Serializers
# =============================================================================


class ApprovalRecordSerializer(serializers.ModelSerializer):
    """
    Serializer for individual approval records.
    Maps to: pending -> approve(A/B) flow in sequence diagram
    """

    approver_email = serializers.EmailField(source="approver.email", read_only=True)
    role_name = serializers.CharField(source="role.name", read_only=True)
    transaction = BlockchainTransactionSerializer(source="tx", read_only=True)

    class Meta:
        model = ApprovalRecord
        fields = [
            "id",
            "request",
            "document",
            "approver",
            "approver_email",
            "role",
            "role_name",
            "signature",
            "remarks",
            "tx",
            "transaction",
            "approved_at",
            "step_index",
        ]
        read_only_fields = ["id", "approved_at"]


class ApprovalRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for approval request workflows.
    Maps to: startApproval -> createRequest -> pending flow in sequence diagram
    """

    document_filename = serializers.CharField(
        source="document.original_filename", read_only=True
    )
    creator_email = serializers.EmailField(source="creator.email", read_only=True)
    approval_records = ApprovalRecordSerializer(many=True, read_only=True)

    class Meta:
        model = ApprovalRequest
        fields = [
            "id",
            "document",
            "document_filename",
            "creator",
            "creator_email",
            "route_json",
            "current_step",
            "status",
            "created_at",
            "completed_at",
            "approval_records",
        ]
        read_only_fields = ["id", "current_step", "created_at", "completed_at"]


class StartApprovalSerializer(serializers.Serializer):
    """
    Input serializer for starting approval workflow.
    Maps to: startApproval(docId) in sequence diagram
    """

    document_id = serializers.UUIDField()
    approver_ids = serializers.ListField(
        child=serializers.UUIDField(), min_length=2, max_length=2
    )
    role_ids = serializers.ListField(
        child=serializers.UUIDField(), min_length=2, max_length=2
    )


class ApproveDocumentSerializer(serializers.Serializer):
    """
    Input serializer for approving a document.
    Maps to: approve(A) and approve(B) in sequence diagram
    """

    approval_request_id = serializers.UUIDField()
    remarks = serializers.CharField(required=False, allow_blank=True, default="")


# =============================================================================
# Audit & Activity Serializers
# =============================================================================


class AuditEventSerializer(serializers.ModelSerializer):
    """
    Serializer for audit events.
    Maps to: Audit logs in sequence diagram
    """

    actor_email = serializers.EmailField(source="actor.email", read_only=True)

    class Meta:
        model = AuditEvent
        fields = [
            "id",
            "event_type",
            "ref_entity",
            "ref_id",
            "actor",
            "actor_email",
            "tx_hash",
            "details_json",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class ActivitySerializer(serializers.ModelSerializer):
    """Serializer for user activity logs"""

    user_email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = Activity
        fields = [
            "id",
            "user",
            "user_email",
            "activity_type",
            "more_details",
            "ip_address",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer for notifications.
    Maps to: completion notice in sequence diagram
    """

    class Meta:
        model = Notification
        fields = ["id", "user", "subject", "message", "is_read", "created_at"]
        read_only_fields = ["id", "created_at"]
