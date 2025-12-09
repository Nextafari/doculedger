from django.contrib import admin
from .models import (
    User,
    Role,
    Permission,
    RolePermission,
    UserRole,
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


class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "first_name", "last_name", "is_active", "created_at")


class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "description")


class PermissionAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "description")


class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ("id", "role", "permission")


class UserRoleAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "role_permission__role__name", "assigned_at")


class ProjectAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "description", "created_at")


class DocumentAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "original_filename", "uploader", "uploaded_at")


class ApprovalRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "document", "creator", "status", "created_at")


class ApprovalRecordAdmin(admin.ModelAdmin):
    list_display = ("id", "approver", "role", "approved_at")


class BlockchainTransactionAdmin(admin.ModelAdmin):
    list_display = ("id", "tx_hash", "status", "created_at")
    search_fields = ("tx_hash",)


class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("id", "event_type", "actor", "document", "created_at")
    search_fields = ("event_type", "actor__email", "document__original_filename")


class ActivityAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "activity_type", "created_at")
    search_fields = ("user__email", "activity_type")


class NotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "message", "is_read", "created_at")
    search_fields = ("user__email", "message")


class EncryptionMetadataAdmin(admin.ModelAdmin):
    list_display = ("id", "document", "key_ref", "created_at")
    search_fields = ("document__original_filename",)


admin.site.register(User, UserAdmin)
admin.site.register(Role, RoleAdmin)
admin.site.register(Permission, PermissionAdmin)
admin.site.register(RolePermission, RolePermissionAdmin)
admin.site.register(UserRole, UserRoleAdmin)
admin.site.register(Project, ProjectAdmin)
admin.site.register(Document, DocumentAdmin)
admin.site.register(ApprovalRequest, ApprovalRequestAdmin)
admin.site.register(ApprovalRecord, ApprovalRecordAdmin)
admin.site.register(BlockchainTransaction, BlockchainTransactionAdmin)
admin.site.register(AuditEvent, AuditEventAdmin)
admin.site.register(Activity, ActivityAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(EncryptionMetadata, EncryptionMetadataAdmin)
