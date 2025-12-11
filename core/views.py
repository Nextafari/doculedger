"""
Views for doculedger - implementing the sequence diagram flows using ONLY existing models.

Sequence Diagram Flows:
1. Upload & Registration: UI -> DocSvc -> HashSvc -> IPFS -> Relayer -> DocRegistry -> Audit
2. Integrity Verification: verify(docId) -> getMetadata -> cat(cid) -> sha256 -> compare -> result+proof
3. Role-Based Approval: startApproval -> pending -> approve(A) -> pending -> approve(B) -> FullyApproved
"""

from drf_yasg.utils import swagger_auto_schema
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction

from core import logger
from core.models import (
    Document,
    Project,
    User,
    Role,
    ApprovalRequest,
    ApprovalRecord,
    BlockchainTransaction,
    AuditEvent,
    Activity,
    Notification,
    Permission,
    RolePermission,
    UserRole,
)
from core.serializers import (
    DocumentSerializer,
    DocumentUploadSerializer,
    VerifyDocumentSerializer,
    VerificationResultSerializer,
    ApprovalRequestSerializer,
    ApprovalRecordSerializer,
    StartApprovalSerializer,
    ApproveDocumentSerializer,
    AuditEventSerializer,
    NotificationSerializer,
    RoleSerializer,
    UserSerializer,
    UserDetailsSerializer,
    UserInviteSerializer,
    ResetPasswordSerializer,
)
from core.utils import HashService, IPFSService, RelayerService


class UserRegistrationViewSet(viewsets.ViewSet):
    """Handle the standalone registration flow at /registration."""

    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    def _assign_owner_role(self, user: User) -> None:
        """Ensure every registered owner user has the owner permission set."""
        role, _ = Role.objects.get_or_create(
            name="owner",
            defaults={"description": "Workspace owner role"},
        )
        permission, _ = Permission.objects.get_or_create(
            name="manage_workspace",
            defaults={"description": "Full workspace management permission"},
        )
        role_permission, _ = RolePermission.objects.get_or_create(
            role=role, permission=permission
        )
        UserRole.objects.get_or_create(user=user, role_permission=role_permission)
    
    @swagger_auto_schema(tags=["api"], request_body=serializer_class)
    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            self._assign_owner_role(user)
        except Exception as e:
            logger.error(f"User registration failed: {str(e)}")
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": "success",
                "message": "User registration successful",
                "data": serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )


class UserViewSet(viewsets.ViewSet):
    """Read-only user endpoints exposed at /users/ and /user/details/<pk>."""

    permission_classes = [IsAuthenticated]
    serializer_class = UserDetailsSerializer

    @swagger_auto_schema(tags=["api"])
    @action(detail=False, methods=["get"], url_path="details")
    def user_data(self, request):
        pk = request.user.pk

        try:
            user = User.objects.get(pk=pk)
            serializer = self.serializer_class(user)
        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "status": "success",
                "message": "User retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    @swagger_auto_schema(tags=["api"])
    def list(self, request):
        users = User.objects.all()
        serializer = self.serializer_class(users, many=True)
        return Response(
            {
                "status": "success",
                "message": "Users retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class RoleListView(APIView):
    """Return all roles except the owner role."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        roles = Role.objects.exclude(name__iexact="owner").order_by("name")
        serializer = RoleSerializer(roles, many=True)
        return Response(
            {
                "status": "success",
                "message": "Roles retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class UserCreationView(APIView):
    """Create a user with the provided role assignment."""

    permission_classes = [IsAuthenticated]
    serializer_class = UserInviteSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        role = getattr(serializer, "role_instance", None)
        if role is None:
            role = Role.objects.get(id=serializer.validated_data["role_id"])
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    email=serializer.validated_data["email"],
                    first_name=serializer.validated_data["first_name"],
                    last_name=serializer.validated_data["last_name"],
                    password=None,
                )

                role_permission = (
                    RolePermission.objects.filter(role=role).first()
                    if role
                    else None
                )

                if not role_permission:
                    raise ValueError("Selected role has no permissions configured.")

                UserRole.objects.get_or_create(
                    user=user, role_permission=role_permission
                )
        except ValueError as exc:
            return Response(
                {"status": "error", "message": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            logger.error(f"User creation failed: {str(exc)}")
            return Response(
                {"status": "error", "message": "Unable to create user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": "success",
                "message": "User created successfully",
                "data": UserDetailsSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ResetPasswordViewSet(viewsets.ViewSet):
    """
    User password management ViewSet.

    Implements password reset and change flows.
    """

    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    @swagger_auto_schema(tags=["api"], request_body=serializer_class)
    @action(detail=False, methods=["post"], url_path="reset-password")
    def reset_password(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        new_password = serializer.validated_data["new_password"]

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "status": "success",
                "message": "Password reset successful"
            },
            status=status.HTTP_200_OK,
        )


# =============================================================================
# 1. UPLOAD & REGISTRATION FLOW
# =============================================================================


class DocumentViewSet(viewsets.ModelViewSet):
    """
    Document management ViewSet.

    Implements Upload & Registration flow from sequence diagram:
    UI -> DocSvc.uploadFile -> HashSvc.sha256 -> IPFS.add ->
    Relayer.metaTx.register -> DocRegistry.register -> Audit
    """

    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter documents by project if specified"""
        queryset = Document.objects.select_related("project", "uploader")
        project_id = self.request.query_params.get("project_id")
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset

    @action(detail=False, methods=["post"], url_path="upload")
    def upload_document(self, request):
        """
        Upload and register a document.

        Sequence: uploadFile -> sha256(file) -> add(IF3) ->
                  metaTx.register(hash,cid,uploader) -> OnConcept(M1)
        """
        serializer = DocumentUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        project_id = serializer.validated_data["project_id"]
        uploaded_file = serializer.validated_data["file"]
        original_filename = serializer.validated_data["original_filename"]

        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response(
                {"error": "Project not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Get or create user (in real system, use request.user)
        uploader = (
            request.user
            if hasattr(request, "user") and isinstance(request.user, User)
            else None
        )

        with transaction.atomic():
            # Step 1: Create document record
            document = Document.objects.create(
                project=project,
                uploader=uploader,
                original_filename=original_filename,
                status="pending",
            )

            # Step 2: HashSvc - Compute SHA256 hash
            file_bytes = uploaded_file.read()
            hash_service = HashService()
            sha256_hash = hash_service.sha256(file_bytes)

            # Step 3: IPFS - Upload to IPFS
            ipfs_service = IPFSService()
            ipfs_cid = ipfs_service.add(file_bytes)

            # Update document with hash and CID
            document.sha256_hash = sha256_hash
            document.cid = ipfs_cid
            document.status = "uploaded"
            document.save()

            # Step 4: Relayer - Submit meta-transaction to blockchain
            relayer_service = RelayerService()
            tx_result = relayer_service.register_document(
                document_hash=sha256_hash,
                cid=ipfs_cid,
                uploader_address=uploader.email if uploader else "system",
            )

            # Step 5: Store blockchain transaction
            blockchain_tx = BlockchainTransaction.objects.create(
                tx_hash=tx_result.get("tx_hash", ""),
                block_number=tx_result.get("block_number"),
                status="confirmed",
                confirmations=1,
                confirmed_at=timezone.now(),
            )

            # Step 6: Audit - Log the upload event
            AuditEvent.objects.create(
                event_type="document_upload",
                ref_entity="Document",
                ref_id=document.id,
                actor=uploader,
                tx_hash=blockchain_tx.tx_hash,
                details_json={
                    "filename": original_filename,
                    "sha256": sha256_hash,
                    "cid": ipfs_cid,
                    "project_id": str(project_id),
                },
            )

            # Log activity
            if uploader:
                Activity.objects.create(
                    user=uploader,
                    activity_type="document_upload",
                    more_details=f"Uploaded {original_filename}",
                )

            return Response(
                {
                    "message": "Document uploaded and registered successfully",
                    "document": DocumentSerializer(document).data,
                    "transaction": {
                        "tx_hash": blockchain_tx.tx_hash,
                        "block_number": blockchain_tx.block_number,
                    },
                },
                status=status.HTTP_201_CREATED,
            )


# =============================================================================
# 2. INTEGRITY VERIFICATION FLOW
# =============================================================================


class VerificationViewSet(viewsets.ViewSet):
    """
    Document verification ViewSet.

    Implements Integrity Verification flow from sequence diagram:
    verify(docId) -> getMetadata(docId) -> cat(cid) -> sha256(fileBytes) ->
    compare hashes -> result(valid, evidence) + proof
    """

    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["post"], url_path="verify")
    def verify_document(self, request):
        """
        Verify document integrity.

        Sequence: verify(docId) -> getMetadata -> cat(cid) ->
                  sha256(fileBytes) -> compare -> result+proof
        """
        serializer = VerifyDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        document_id = serializer.validated_data["document_id"]

        try:
            document = Document.objects.get(id=document_id)
        except Document.DoesNotExist:
            return Response(
                {"error": "Document not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Step 1: getMetadata - Get stored hash and CID
        stored_hash = document.sha256_hash
        stored_cid = document.cid

        if not stored_hash or not stored_cid:
            return Response(
                {"error": "Document not fully registered"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 2: IPFS.cat - Retrieve file from IPFS
        ipfs_service = IPFSService()
        file_bytes = ipfs_service.cat(stored_cid)

        # Step 3: HashSvc.sha256 - Compute hash of retrieved file
        hash_service = HashService()
        computed_hash = hash_service.sha256(file_bytes)

        # Step 4: Compare hashes
        is_valid = computed_hash == stored_hash

        # Step 5: Generate proof
        proof_data = {
            "verification_method": "sha256_ipfs",
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "cid": stored_cid,
            "timestamp": timezone.now().isoformat(),
        }

        verified_at = timezone.now()

        # Step 6: Log verification in AuditEvent
        verifier = (
            request.user
            if hasattr(request, "user") and isinstance(request.user, User)
            else None
        )
        AuditEvent.objects.create(
            event_type="document_verification",
            ref_entity="Document",
            ref_id=document.id,
            actor=verifier,
            details_json={
                "is_valid": is_valid,
                "stored_hash": stored_hash,
                "computed_hash": computed_hash,
                "proof": proof_data,
            },
        )

        # Update document status
        if is_valid:
            document.status = "verified"
            document.save()

        result = VerificationResultSerializer(
            {
                "document_id": document.id,
                "is_valid": is_valid,
                "stored_hash": stored_hash,
                "computed_hash": computed_hash,
                "cid": stored_cid,
                "proof": proof_data,
                "verified_at": verified_at,
                "message": (
                    "Document integrity verified successfully"
                    if is_valid
                    else "Document integrity verification failed - hash mismatch"
                ),
            }
        )

        return Response(result.data, status=status.HTTP_200_OK)


# =============================================================================
# 3. ROLE-BASED APPROVAL FLOW
# =============================================================================


class ApprovalViewSet(viewsets.ModelViewSet):
    """
    Approval workflow ViewSet.

    Implements Role-Based Approval flow from sequence diagram:
    startApproval -> createRequest -> pending -> approve(A) -> pending ->
    approve(B) -> FullyApproved -> completion notice
    """

    queryset = ApprovalRequest.objects.all()
    serializer_class = ApprovalRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Get approval requests with related data"""
        return ApprovalRequest.objects.select_related(
            "document", "creator"
        ).prefetch_related("approval_records__approver", "approval_records__role")

    @action(detail=False, methods=["post"], url_path="start")
    def start_approval(self, request):
        """
        Start approval workflow for a document.

        Sequence: startApproval(docId) -> createRequest(docId) -> pending
        """
        serializer = StartApprovalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        document_id = serializer.validated_data["document_id"]
        approver_ids = serializer.validated_data["approver_ids"]
        role_ids = serializer.validated_data["role_ids"]

        try:
            document = Document.objects.get(id=document_id)
        except Document.DoesNotExist:
            return Response(
                {"error": "Document not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Validate approvers and roles exist
        approvers = User.objects.filter(id__in=approver_ids)
        roles = Role.objects.filter(id__in=role_ids)

        if len(approvers) != 2 or len(roles) != 2:
            return Response(
                {"error": "Must provide exactly 2 valid approvers and 2 valid roles"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        creator = (
            request.user
            if hasattr(request, "user") and isinstance(request.user, User)
            else None
        )

        with transaction.atomic():
            # Create approval request
            approval_request = ApprovalRequest.objects.create(
                document=document,
                creator=creator,
                route_json={
                    "approvers": [str(aid) for aid in approver_ids],
                    "roles": [str(rid) for rid in role_ids],
                },
                current_step=0,
                status="pending",
            )

            # Create approval records for each approver
            for idx, (approver, role) in enumerate(zip(approvers, roles)):
                ApprovalRecord.objects.create(
                    request=approval_request,
                    document=document,
                    approver=approver,
                    role=role,
                    step_index=idx,
                )

            # Log audit event
            AuditEvent.objects.create(
                event_type="approval_started",
                ref_entity="ApprovalRequest",
                ref_id=approval_request.id,
                actor=creator,
                details_json={
                    "document_id": str(document_id),
                    "approvers": [approver.email for approver in approvers],
                    "roles": [role.name for role in roles],
                },
            )

            # Send notifications to approvers
            for approver in approvers:
                Notification.objects.create(
                    user=approver,
                    subject="Approval Request",
                    message=f"You have been assigned to approve document: {document.original_filename}",
                )

            return Response(
                {
                    "message": "Approval workflow started successfully",
                    "approval_request": ApprovalRequestSerializer(
                        approval_request
                    ).data,
                },
                status=status.HTTP_201_CREATED,
            )

    @action(detail=False, methods=["post"], url_path="approve")
    def approve_document(self, request):
        """
        Approve a document (maps to approve.A or approve.B in sequence).

        Sequence: pending -> approve(A/B) -> metaTx.approve ->
                  OffConcept(M1) -> stored -> [pending or FullyApproved]
        """
        serializer = ApproveDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        approval_request_id = serializer.validated_data["approval_request_id"]
        remarks = serializer.validated_data.get("remarks", "")

        try:
            approval_request = ApprovalRequest.objects.get(id=approval_request_id)
        except ApprovalRequest.DoesNotExist:
            return Response(
                {"error": "Approval request not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        approver = (
            request.user
            if hasattr(request, "user") and isinstance(request.user, User)
            else None
        )

        # Find the pending approval record for this approver
        approval_record = (
            ApprovalRecord.objects.filter(
                request=approval_request, approver=approver, approved_at__isnull=True
            )
            .order_by("step_index")
            .first()
        )

        if not approval_record:
            return Response(
                {"error": "No pending approval found for this user"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            # Submit meta-transaction to blockchain
            relayer_service = RelayerService()
            tx_result = relayer_service.approve_document(
                document_id=str(approval_request.document.id),
                approver_address=approver.email if approver else "system",
                role=approval_record.role.name,
            )

            # Create blockchain transaction record
            blockchain_tx = BlockchainTransaction.objects.create(
                tx_hash=tx_result.get("tx_hash", ""),
                block_number=tx_result.get("block_number"),
                status="confirmed",
                confirmations=1,
                confirmed_at=timezone.now(),
            )

            # Update approval record
            approval_record.remarks = remarks
            approval_record.approved_at = timezone.now()
            approval_record.tx = blockchain_tx
            approval_record.save()

            # Update approval request progress
            approval_request.current_step += 1
            total_approvals = approval_request.approval_records.count()
            completed_approvals = approval_request.approval_records.filter(
                approved_at__isnull=False
            ).count()

            # Check if fully approved
            if completed_approvals >= total_approvals:
                approval_request.status = "completed"
                approval_request.completed_at = timezone.now()
                approval_request.document.status = "approved"
                approval_request.document.save()

                # Send completion notice
                Notification.objects.create(
                    user=approval_request.creator,
                    subject="Approval Completed",
                    message=f"Document {approval_request.document.original_filename} has been fully approved.",
                )

            approval_request.save()

            # Log audit event
            AuditEvent.objects.create(
                event_type="document_approved",
                ref_entity="ApprovalRecord",
                ref_id=approval_record.id,
                actor=approver,
                tx_hash=blockchain_tx.tx_hash,
                details_json={
                    "approval_request_id": str(approval_request.id),
                    "document_id": str(approval_request.document.id),
                    "role": approval_record.role.name,
                    "step": approval_record.step_index,
                    "remarks": remarks,
                    "is_final": approval_request.status == "completed",
                },
            )

            return Response(
                {
                    "message": "Document approved successfully",
                    "approval_record": ApprovalRecordSerializer(approval_record).data,
                    "approval_request": ApprovalRequestSerializer(
                        approval_request
                    ).data,
                    "is_fully_approved": approval_request.status == "completed",
                },
                status=status.HTTP_200_OK,
            )


# =============================================================================
# 4. AUDIT LOGS
# =============================================================================


class AuditViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Audit logs ViewSet (read-only).

    Provides access to all audit events tracked throughout the system.
    """

    queryset = AuditEvent.objects.all()
    serializer_class = AuditEventSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter audit logs by entity or actor"""
        queryset = AuditEvent.objects.select_related("actor").order_by("-created_at")

        ref_entity = self.request.query_params.get("ref_entity")
        ref_id = self.request.query_params.get("ref_id")
        event_type = self.request.query_params.get("event_type")

        if ref_entity:
            queryset = queryset.filter(ref_entity=ref_entity)
        if ref_id:
            queryset = queryset.filter(ref_id=ref_id)
        if event_type:
            queryset = queryset.filter(event_type=event_type)

        return queryset


