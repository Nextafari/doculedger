from django.db.models.signals import post_migrate
from django.dispatch import receiver

from .models import Permission, Role


@receiver(post_migrate)
def seed_core_roles_permissions(sender, **kwargs):
    if sender.name != "core":
        return

    Role.objects.get_or_create(
        name="owner",
        defaults={"description": "Workspace owner role"},
    )
    Permission.objects.get_or_create(
        name="manage_workspace",
        defaults={"description": "Full workspace management permission"},
    )
