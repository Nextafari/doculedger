import uuid
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)

from django.utils import timezone


def now():
    return timezone.now()


class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class GasAddress(models.Model):
    """
    Represents a gas address for blockchain transactions.
    This is used to track the address that pays for gas fees.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, blank=True, null=True)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="gas_addresses"
    )
    address = models.CharField(max_length=128, unique=True)  # e.g. Ethereum address
    modified = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Gas Address {self.address} for {self.project.name}"


class UserManager(BaseUserManager):
    def create_user(
        self,
        email,
        first_name,
        last_name,
        password=None,
        **extra_fields,
    ):
        """
        Create and save a User with credentials provided.
        """
        if not email:
            raise ValueError("User must provide a valid email address")

        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self,
        email,
        first_name,
        last_name,
        password=None,
        **extra_fields,
    ):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            password=password,
        )
        user.is_staff = True
        user.is_admin = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=120, blank=True)
    last_name = models.CharField(max_length=120, blank=True)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=32, blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    # This overwrites django's default user model's username to a
    # username of choice
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    def __str__(self):
        return f"{self.first_name} {self.last_name} <{self.email}>"


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return self.name


class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class RolePermission(models.Model):
    """
    Join table linking roles to permissions
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission = models.ForeignKey(
        Permission, on_delete=models.CASCADE, related_name="permission_roles"
    )
    created_at = models.DateTimeField(default=now)

    class Meta:
        unique_together = ("role", "permission")

    def __str__(self):
        return f"{self.role.name} -> {self.permission.name}"


class UserRole(models.Model):
    """
    Join table linking users to roles
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_roles")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_roles")
    assigned_at = models.DateTimeField(default=now)

    class Meta:
        unique_together = ("user", "role")

    def __str__(self):
        return f"{self.user.email} as {self.role.name}"


class Document(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("uploaded", "Uploaded"),
        ("verified", "Verified"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="documents"
    )
    uploader = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="uploaded_documents"
    )
    original_filename = models.CharField(max_length=512)
    s3_url = models.CharField(max_length=1024, blank=True, null=True)  # or file path
    cid = models.CharField(
        max_length=256, blank=True, null=True, db_index=True
    )  # IPFS CID
    sha256_hash = models.CharField(
        max_length=128, blank=True, null=True, unique=False
    )  # index if needed
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="pending")
    uploaded_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.original_filename} ({self.id})"


class EncryptionMetadata(models.Model):
    """
    Encryption details stored off-chain; do NOT store secret key material publicly.
    Keep this table in a secure DB and limit access.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.OneToOneField(
        Document, on_delete=models.CASCADE, related_name="encryption_metadata"
    )
    algorithm = models.CharField(max_length=128)  # e.g., AES-256-GCM
    key_ref = models.CharField(
        max_length=512, blank=True, null=True
    )  # reference to KMS entry or key id
    iv = models.CharField(max_length=128, blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Encryption metadata for {self.document_id}"


class BlockchainTransaction(models.Model):
    """
    Metadata about the blockchain transaction used to record the document/approval.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tx_hash = models.CharField(max_length=128, unique=True)
    block_number = models.BigIntegerField(blank=True, null=True)
    status = models.CharField(
        max_length=64, blank=True, null=True
    )  # e.g., pending, confirmed, failed
    confirmations = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=now)
    confirmed_at = models.DateTimeField(blank=True, null=True)
    gas_fee = models.DecimalField(
        max_digits=38, decimal_places=18, blank=True, null=True
    )

    def __str__(self):
        return f"{self.tx_hash} ({self.status})"


class Signature(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="signatures")
    image_url = models.CharField(
        max_length=1024, blank=True, null=True
    )  # if storing signature image
    hash = models.CharField(
        max_length=128, blank=True, null=True
    )  # content hash of signature if needed
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Signature {self.id} by {self.user.email}"


class ApprovalRequest(models.Model):
    """
    Represents an approval workflow instance for a document.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        Document, on_delete=models.CASCADE, related_name="approval_requests"
    )
    creator = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_approval_requests",
    )
    route_json = models.JSONField(blank=True, null=True)  # route or approver list
    current_step = models.IntegerField(default=0)
    status = models.CharField(
        max_length=64, default="pending"
    )  # pending, in_progress, completed, cancelled
    created_at = models.DateTimeField(default=now)
    completed_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"ApprovalRequest {self.id} for {self.document_id}"


class ApprovalRecord(models.Model):
    """
    Each approval step recorded for an approval request.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request = models.ForeignKey(
        ApprovalRequest, on_delete=models.CASCADE, related_name="approval_records"
    )
    document = models.ForeignKey(
        Document, on_delete=models.CASCADE, related_name="approval_records"
    )
    approver = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="approvals"
    )
    role = models.ForeignKey(
        Role, on_delete=models.SET_NULL, null=True, related_name="approval_records"
    )
    signature = models.ForeignKey(
        Signature, on_delete=models.SET_NULL, null=True, related_name="approval_records"
    )
    remarks = models.TextField(blank=True, null=True)
    tx = models.ForeignKey(
        BlockchainTransaction,
        on_delete=models.SET_NULL,
        null=True,
        related_name="approval_records",
    )
    approved_at = models.DateTimeField(blank=True, null=True)
    step_index = models.IntegerField(default=0)

    def __str__(self):
        return f"ApprovalRecord {self.id} (step {self.step_index})"


class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    subject = models.CharField(max_length=255)
    message = models.TextField(blank=True, null=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Notification to {self.user.email}: {self.subject}"


class Activity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="activities"
    )
    activity_type = models.CharField(max_length=128)
    more_details = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"{self.activity_type} by {self.user and self.user.email}"


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=128)
    ref_entity = models.CharField(
        max_length=128, blank=True, null=True
    )  # e.g., "Document", "ApprovalRequest"
    ref_id = models.UUIDField(blank=True, null=True)  # referenced entity id
    actor = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="audit_events"
    )
    tx_hash = models.CharField(
        max_length=128, blank=True, null=True
    )  # optional tx link
    details_json = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"AuditEvent {self.event_type} at {self.created_at}"
