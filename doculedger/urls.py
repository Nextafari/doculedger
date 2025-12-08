"""
URL configuration for doculedger project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Swagger/OpenAPI schema view
schema_view = get_schema_view(
    openapi.Info(
        title="DocuLedger API",
        default_version="v1",
        description="""
        DocuLedger API - Document Management with Blockchain Verification
        
        ## Features
        
        ### Upload & Registration (F1, F2, F3)
        - Upload documents with SHA256 hashing
        - Store on IPFS for decentralized storage
        - Register on blockchain via meta-transactions (gasless)
        
        ### Integrity Verification (F4)
        - Verify document integrity by comparing hashes
        - Retrieve content from IPFS and recompute hash
        - Generate cryptographic proof of verification
        
        ### Role-Based Approval (F5)
        - Create multi-step approval workflows
        - Track approval status and history
        - Record approvals on blockchain
        
        ### Audit Logs (F6)
        - Comprehensive audit trail for all operations
        - Document registration events
        - Approval events (ApprovalRecorded, FinalApprovalRecorded)
        - Verification events
        
        ### Gasless Transactions (F7)
        - Meta-transaction support for gasless UX
        - Relayer pays gas on behalf of users
        """,
        terms_of_service="https://www.doculedger.io/terms/",
        contact=openapi.Contact(email="support@doculedger.io"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # API v1 - Core endpoints
    path("api/", include("core.urls")),
    # API Documentation
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path(
        "redoc/",
        schema_view.with_ui("redoc", cache_timeout=0),
        name="schema-redoc",
    ),
    path(
        "swagger.json",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
]
