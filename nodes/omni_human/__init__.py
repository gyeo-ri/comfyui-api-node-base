from nodes.base import ComfyUICustomNodeBase
from typing import Any, Dict, Optional
import hmac
import hashlib
import datetime
from urllib.parse import quote


class OmniHumanNode(ComfyUICustomNodeBase):
    """OmniHuman API node for generating avatar videos."""

    # BytePlus API constants
    SERVICE = "cv"
    REGION = "ap-singapore-1"
    BASE_URL = "https://cv.byteplusapi.com"
    API_VERSION = "2024-06-06"

    @classmethod
    def INPUT_TYPES(cls) -> Dict[str, Any]:
        """Defines the input types for the OmniHuman node."""
        return {
            "required": {
                "access_key_id": (
                    "STRING",
                    {
                        "default": "",
                        "display_name": "Access Key ID",
                    },
                ),
                "secret_access_key": (
                    "STRING",
                    {
                        "default": "",
                        "display_name": "Secret Access Key",
                    },
                ),
                "req_key": (
                    "STRING",
                    {
                        "default": "realman_avatar_picture_omni15_cv",
                        "display_name": "Request Key",
                    },
                ),
                "image_url": ("STRING", {"default": "", "display_name": "Image URL"}),
                "audio_url": ("STRING", {"default": "", "display_name": "Audio URL"}),
            },
            "optional": {
                "mask_url": ("STRING", {"default": "", "display_name": "Mask URL"}),
            },
        }

    RETURN_TYPES = ("JSON",)
    RETURN_NAMES = ("result",)
    FUNCTION = "run"
    CATEGORY = "omni_human"

    def __init__(self):
        """Initialize the node and prepare for API authentication."""
        super().__init__()
        self.access_key_id: Optional[str] = None
        self.secret_access_key: Optional[str] = None

    @staticmethod
    def _sha256(data: bytes) -> bytes:
        """Calculate SHA256 hash of data."""
        return hashlib.sha256(data).digest()

    @staticmethod
    def _hmac_sha256(key: bytes, data: bytes) -> bytes:
        """Calculate HMAC-SHA256 signature."""
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def _get_amz_date(dt: datetime.datetime) -> str:
        """Get AMZ date string in format: YYYYMMDDTHHMMSSZ."""
        return dt.strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _get_date_stamp(dt: datetime.datetime) -> str:
        """Get date stamp in format: YYYYMMDD."""
        return dt.strftime("%Y%m%d")

    def _get_signing_key(
        self, secret_key: str, date_stamp: str, region: str, service: str
    ) -> bytes:
        """Generate signing key for HMAC-SHA256 signature (AWS Signature Version 4 style)."""
        k_date = self._hmac_sha256(
            f"AWS4{secret_key}".encode("utf-8"), date_stamp.encode("utf-8")
        )
        k_region = self._hmac_sha256(k_date, region.encode("utf-8"))
        k_service = self._hmac_sha256(k_region, service.encode("utf-8"))
        k_signing = self._hmac_sha256(k_service, b"aws4_request")
        return k_signing

    def _create_canonical_request(
        self,
        method: str,
        uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
    ) -> str:
        """Create canonical request string for signature calculation."""
        # Sort headers by name
        sorted_headers = sorted(headers.items())
        canonical_headers = "".join(
            f"{k.lower()}:{v.strip()}\n" for k, v in sorted_headers
        )
        signed_headers = ";".join(k.lower() for k, _ in sorted_headers)

        canonical_request = f"{method}\n"
        canonical_request += f"{uri}\n"
        canonical_request += f"{query_string}\n"
        canonical_request += f"{canonical_headers}\n"
        canonical_request += f"{signed_headers}\n"
        canonical_request += f"{payload_hash}"

        return canonical_request

    def _create_string_to_sign(
        self,
        algorithm: str,
        amz_date: str,
        date_stamp: str,
        region: str,
        service: str,
        canonical_request: str,
    ) -> str:
        """Create string to sign for signature calculation."""
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = f"{algorithm}\n"
        string_to_sign += f"{amz_date}\n"
        string_to_sign += f"{credential_scope}\n"
        string_to_sign += hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        return string_to_sign

    def generate_authorization_header(
        self,
        method: str,
        uri: str,
        query_params: Dict[str, str],
        headers: Dict[str, str],
        payload: str,
    ) -> str:
        """Generate HMAC-SHA256 Authorization header for BytePlus API."""
        if not self.secret_access_key or not self.access_key_id:
            raise ValueError(
                "access_key_id and secret_access_key must be set before generating authorization header"
            )

        # Prepare date and time
        now = datetime.datetime.utcnow()
        amz_date = self._get_amz_date(now)
        date_stamp = self._get_date_stamp(now)

        # Add required headers
        headers["host"] = uri.split("://")[1].split("/")[0]
        headers["x-amz-date"] = amz_date

        # Calculate payload hash
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        # Create query string
        sorted_params = sorted(query_params.items())
        query_string = "&".join(
            f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in sorted_params
        )

        # Create canonical request
        canonical_request = self._create_canonical_request(
            method, uri, query_string, headers, payload_hash
        )

        # Create string to sign
        algorithm = "HMAC-SHA256"
        string_to_sign = self._create_string_to_sign(
            algorithm,
            amz_date,
            date_stamp,
            self.REGION,
            self.SERVICE,
            canonical_request,
        )

        # Generate signing key
        signing_key = self._get_signing_key(
            self.secret_access_key, date_stamp, self.REGION, self.SERVICE
        )

        # Calculate signature
        signature = self._hmac_sha256(signing_key, string_to_sign.encode("utf-8"))
        signature_hex = signature.hex()

        # Create authorization header
        credential = (
            f"{self.access_key_id}/{date_stamp}/{self.REGION}/{self.SERVICE}/request"
        )
        signed_headers = ";".join(
            k.lower() for k, _ in sorted(headers.items(), key=lambda x: x[0].lower())
        )

        authorization = (
            f"{algorithm} Credential={credential}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature_hex}"
        )

        return authorization


if __name__ == "__main__":
    # Need to add run test
    pass
