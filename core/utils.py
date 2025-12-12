"""
Utility services for doculedger - implementing external service integrations.

Maps to sequence diagram components:
- HashSvc: sha256(file) -> hash
- IPFSService: add(file) -> CID, cat(CID) -> fileBytes
- RelayerService: metaTx.register, metaTx.approve -> tx_hash
"""

import hashlib
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, Any

import boto3
from botocore.exceptions import ClientError
from django.conf import settings


class HashService:
    """
    Hash service for computing file hashes.
    Maps to: HashSvc in sequence diagram
    """

    @staticmethod
    def sha256(file_bytes: bytes) -> str:
        """
        Compute SHA256 hash of file bytes.

        Maps to: sha256(file) in sequence diagram

        Args:
            file_bytes: Raw file bytes

        Returns:
            Hexadecimal SHA256 hash string
        """
        return hashlib.sha256(file_bytes).hexdigest()

    @staticmethod
    def keccak256(file_bytes: bytes) -> str:
        """
        Compute Keccak256 hash (Ethereum-style).

        Note: Requires additional library (sha3) in production
        For now, falls back to SHA256
        """
        # TODO: Implement actual Keccak256 when web3 is integrated
        # from Crypto.Hash import keccak
        # k = keccak.new(digest_bits=256)
        # k.update(file_bytes)
        # return k.hexdigest()
        return hashlib.sha256(file_bytes).hexdigest()


class IPFSService:
    """
    IPFS service for decentralized file storage.
    Maps to: IPFS in sequence diagram
    """

    def __init__(self, ipfs_url: str = None):
        """
        Initialize IPFS service.

        Args:
            ipfs_url: IPFS node URL (default: http://localhost:5001)
        """
        self.ipfs_url = ipfs_url or "http://localhost:5001"
        # TODO: Initialize IPFS client in production
        # import ipfshttpclient
        # self.client = ipfshttpclient.connect(self.ipfs_url)

    def add(self, file_bytes: bytes) -> str:
        """
        Upload file to IPFS and return CID.

        Maps to: add(file) -> CID in sequence diagram

        Args:
            file_bytes: Raw file bytes to upload

        Returns:
            IPFS Content Identifier (CID)
        """
        # TODO: Implement actual IPFS upload in production
        # result = self.client.add_bytes(file_bytes)
        # return result

        # Mock implementation for development
        mock_cid = f"Qm{hashlib.sha256(file_bytes).hexdigest()[:44]}"
        return mock_cid

    def cat(self, cid: str) -> bytes:
        """
        Retrieve file from IPFS by CID.

        Maps to: cat(cid) -> fileBytes in sequence diagram

        Args:
            cid: IPFS Content Identifier

        Returns:
            File bytes
        """
        # TODO: Implement actual IPFS retrieval in production
        # file_bytes = self.client.cat(cid)
        # return file_bytes

        # Mock implementation for development
        # In production, this would retrieve actual file from IPFS
        return b"mock_file_content"

    def pin(self, cid: str) -> bool:
        """
        Pin file on IPFS to prevent garbage collection.

        Args:
            cid: IPFS Content Identifier

        Returns:
            True if pinned successfully
        """
        # TODO: Implement actual IPFS pinning in production
        # self.client.pin.add(cid)
        # return True
        return True


class S3Service:
    """Uploader backed by AWS S3 via boto3."""

    def __init__(
        self,
        bucket_name: str | None = None,
        region_name: str | None = None,
        prefix: str = "documents",
        fallback_dir: str | None = None,
    ):
        self.bucket_name = bucket_name or getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
        self.region_name = region_name or getattr(settings, "AWS_REGION", None)
        self.prefix = prefix.strip("/").strip() or "documents"
        self.fallback_dir = fallback_dir or getattr(settings, "DOCUMENT_STORAGE_FALLBACK_DIR", "media/documents")
        self.fallback_url = getattr(settings, "DOCUMENT_STORAGE_FALLBACK_URL", "/media/")
        self.use_disk = self.bucket_name is None
        if not self.use_disk:
            self.client = boto3.client("s3", region_name=self.region_name)

    def upload(self, file_bytes: bytes, filename: str, content_type: str | None = None) -> str:
        """Upload bytes to S3 and return the public object URL."""

        if self.use_disk:
            return self._save_to_disk(file_bytes, filename)

        key = f"{self.prefix}/{uuid.uuid4().hex}_{filename}"
        extra_args = {}
        if content_type:
            extra_args["ContentType"] = content_type

        try:
            self.client.put_object(
                Bucket=self.bucket_name, Key=key, Body=file_bytes, **extra_args
            )
        except ClientError as exc:
            logger = logging.getLogger(__name__)
            logger.error("Failed to upload to S3, falling back to disk: %s", exc)
            return self._save_to_disk(file_bytes, filename)

        base_url = (
            f"https://{self.bucket_name}.s3.amazonaws.com/{key}"
            if not self.region_name or self.region_name == "us-east-1"
            else f"https://{self.bucket_name}.s3-{self.region_name}.amazonaws.com/{key}"
        )
        return base_url

    def _save_to_disk(self, file_bytes: bytes, filename: str) -> str:
        """Persist the file locally and return a URL similar to S3."""

        base_path = Path(self.fallback_dir).resolve()
        key = f"{self.prefix}/{uuid.uuid4().hex}_{filename}"
        target_path = base_path / key
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "wb") as fh:
            fh.write(file_bytes)

        public_url = os.path.join(self.fallback_url.rstrip("/"), key)
        return public_url


class RelayerService:
    """
    Blockchain relayer service for gasless meta-transactions.
    Maps to: Relayer in sequence diagram
    """

    def __init__(self, relayer_url: str = None):
        """
        Initialize relayer service.

        Args:
            relayer_url: Relayer endpoint URL
        """
        self.relayer_url = relayer_url or "http://localhost:8545"
        # TODO: Initialize Web3 provider in production
        # from web3 import Web3
        # self.w3 = Web3(Web3.HTTPProvider(self.relayer_url))

    def register_document(
        self, document_hash: str, cid: str, uploader_address: str
    ) -> Dict[str, Any]:
        """
        Submit meta-transaction to register document on blockchain.

        Maps to: metaTx.register(hash, cid, uploader) in sequence diagram

        Args:
            document_hash: SHA256 hash of document
            cid: IPFS Content Identifier
            uploader_address: Uploader's blockchain address

        Returns:
            Transaction result with tx_hash and block_number
        """
        # TODO: Implement actual blockchain transaction in production
        # Build meta-transaction
        # meta_tx = {
        #     'from': uploader_address,
        #     'to': DOC_REGISTRY_PROXY_ADDRESS,
        #     'data': contract.encodeABI(fn_name='register',
        #                                args=[document_hash, cid, uploader_address])
        # }
        # Submit to relayer
        # tx_hash = self.relayer.submit_meta_tx(meta_tx)
        # receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        # return {'tx_hash': tx_hash, 'block_number': receipt['blockNumber']}

        # Mock implementation for development
        mock_tx_hash = f"0x{uuid.uuid4().hex}"
        return {
            "tx_hash": mock_tx_hash,
            "block_number": 12345678,
            "status": "confirmed",
        }

    def approve_document(
        self, document_id: str, approver_address: str, role: str
    ) -> Dict[str, Any]:
        """
        Submit meta-transaction to record approval on blockchain.

        Maps to: metaTx.approve.A / metaTx.approve.B in sequence diagram

        Args:
            document_id: Document identifier
            approver_address: Approver's blockchain address
            role: Approver role (A or B)

        Returns:
            Transaction result with tx_hash and block_number
        """
        # TODO: Implement actual blockchain transaction in production
        # Build meta-transaction
        # meta_tx = {
        #     'from': approver_address,
        #     'to': APPROVAL_REGISTRY_PROXY_ADDRESS,
        #     'data': contract.encodeABI(fn_name='approve',
        #                                args=[document_id, approver_address, role])
        # }
        # Submit to relayer
        # tx_hash = self.relayer.submit_meta_tx(meta_tx)
        # receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        # return {'tx_hash': tx_hash, 'block_number': receipt['blockNumber']}

        # Mock implementation for development
        mock_tx_hash = f"0x{uuid.uuid4().hex}"
        return {
            "tx_hash": mock_tx_hash,
            "block_number": 12345679,
            "status": "confirmed",
        }

    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """
        Get transaction status from blockchain.

        Args:
            tx_hash: Transaction hash

        Returns:
            Transaction status information
        """
        # TODO: Implement actual status check in production
        # receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        # return {
        #     'tx_hash': tx_hash,
        #     'status': 'confirmed' if receipt['status'] == 1 else 'failed',
        #     'block_number': receipt['blockNumber'],
        #     'confirmations': self.w3.eth.block_number - receipt['blockNumber']
        # }

        # Mock implementation for development
        return {
            "tx_hash": tx_hash,
            "status": "confirmed",
            "block_number": 12345678,
            "confirmations": 5,
        }


class ProxyPatternService:
    """
    Utility for interacting with upgradeable proxy contracts.
    Maps to: DocRegistry Proxy and ApproveRegistry Proxy in sequence diagram
    """

    @staticmethod
    def get_implementation_address(proxy_address: str) -> str:
        """
        Get implementation contract address from proxy.

        Args:
            proxy_address: Proxy contract address

        Returns:
            Implementation contract address
        """
        # TODO: Implement actual proxy pattern lookup in production
        # from web3 import Web3
        # w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        # storage_slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
        # implementation = w3.eth.get_storage_at(proxy_address, storage_slot)
        # return w3.to_checksum_address(implementation[-20:])

        # Mock implementation
        return f"0x{uuid.uuid4().hex[:40]}"


# =============================================================================
# Helper Functions
# =============================================================================


def get_client_ip(request) -> str:
    """
    Extract client IP address from request.

    Args:
        request: Django request object

    Returns:
        Client IP address
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip
