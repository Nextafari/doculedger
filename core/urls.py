"""
URL Configuration for doculedger core app.

Maps to sequence diagram flows:
- Document upload & registration
- Document verification
- Approval workflows
- Audit logs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .views import (
    AdminCreateUserView,
    AuditViewSet,
    ApprovalViewSet,
    DocumentViewSet,
    ResetPasswordViewSet,
    RoleListView,
    VerificationViewSet,
    UserViewSet,
    UserRegistrationViewSet,
    CreateProjectView,
)


# Create router for ViewSets
router = DefaultRouter()
router.register(r"user/registration", UserRegistrationViewSet, basename="user-registration")
router.register(r"users", UserViewSet, basename="user-details")
router.register(r"documents", DocumentViewSet, basename="document")
router.register(r"verification", VerificationViewSet, basename="verification")
router.register(r"approvals", ApprovalViewSet, basename="approval")
router.register(r"audit", AuditViewSet, basename="audit")
router.register(r"", ResetPasswordViewSet, basename="reset-password")

urlpatterns = [
    path("", include(router.urls)),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("roles/", RoleListView.as_view(), name="roles-list"),
    path("admin/create/users/", AdminCreateUserView.as_view(), name="user-create"),
    path("projects/", CreateProjectView.as_view(), name="project-create"),
]

# Available endpoints:
# POST   /api/documents/upload/           - Upload and register document
# GET    /api/documents/                  - List all documents
# GET    /api/documents/{id}/             - Get document detail
# POST   /api/verification/verify/        - Verify document integrity
# POST   /api/approvals/start/            - Start approval workflow
# POST   /api/approvals/approve/          - Approve document
# GET    /api/approvals/                  - List approval requests
# GET    /api/approvals/{id}/             - Get approval request detail
# GET    /api/audit/                      - List audit events
# GET    /api/audit/{id}/                 - Get audit event detail
