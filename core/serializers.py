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

from core.models import (
    User,
    Role,
    RolePermission,
    Project,
    ProjectMember,
    Document,
    ApprovalRequest,
    ApprovalRecord,
    BlockchainTransaction,
    AuditEvent,
    Activity,
    Notification,
    EncryptionMetadata,
    UserRole,
)
from core.validators import validate_phonenumber

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
            "password",
            "is_active",
            "created_at",
        ]

        extra_kwargs = {
            "password": {"write_only": True},
            "id": {"read_only": True},
            "created_at": {"read_only": True},
            "is_active": {"read_only": True},
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)

        mobile = validated_data.get("mobile")
        if mobile:
            validate_phonenumber(mobile)

        if not password:
            raise serializers.ValidationError({"password": "Password is required."})

        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserDetailsSerializer(serializers.ModelSerializer):
    """Serializer for detailed User model view"""
    role = serializers.SerializerMethodField(method_name="get_user_role")

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "mobile",
            "role",
            "is_active",
            "created_at",
        ]

    def get_user_role(self, obj):
        user_role = UserRole.objects.select_related("role_permission").filter(user=obj).first()

        try:
            role_name = user_role.role_permission.role.name if user_role else None
        except AttributeError:
            role_name = None

        return role_name


class UserInviteSerializer(serializers.Serializer):
    """Serializer for creating users with a non-owner role."""

    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=120)
    last_name = serializers.CharField(max_length=120)
    role_id = serializers.UUIDField(write_only=True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists.")
        return value

    def validate_role_id(self, value):
        try:
            role = Role.objects.get(id=value)
        except Role.DoesNotExist as exc:
            raise serializers.ValidationError("Role not found.") from exc

        if role.name.lower() == "owner":
            raise serializers.ValidationError("Owner role cannot be assigned via this endpoint.")

        role_permission_exists = RolePermission.objects.filter(role=role).exists()
        if not role_permission_exists:
            raise serializers.ValidationError("Selected role has no permissions configured.")

        self.role_instance = role
        return value


class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for resetting user password"""

    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Role model"""

    class Meta:
        model = Role
        fields = ["id", "name", "description"]
        read_only_fields = ["id"]


class ProjectMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectMember
        fields = ["id", "user", "role", "joined_at"]
        read_only_fields = ["id", "joined_at"]


class CreateProjectSerializer(serializers.ModelSerializer):
    """Serializer for Project model"""
    project_members = ProjectMemberSerializer(many=True, write_only=True)

    class Meta:
        model = Project
        fields = ["id", "name", "description", "project_members", "created_at"]
        read_only_fields = ["id", "created_at"]

    def create(self, validated_data):
        project_members_data = validated_data.pop("project_members", [])
        project = Project.objects.create(**validated_data)

        for member_data in project_members_data:
            ProjectMember.objects.create(project=project, **member_data)

        return project


class ProjectSerializer(serializers.ModelSerializer):
    """Serializer for Project model"""
    project_members = ProjectMemberSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = ["id", "name", "description", "project_members", "created_at"]
        read_only_fields = ["id", "project_members", "created_at"]


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


class SetApproversSerializer(serializers.Serializer):
    document_id = serializers.UUIDField()
    approver_ids = serializers.ListField(
        child=serializers.UUIDField(), min_length=1
    )
