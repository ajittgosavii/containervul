"""Pydantic data models — the contract between all layers."""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


# ── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class CloudProviderType(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ServiceType(str, Enum):
    EKS = "eks"
    ECS = "ecs"
    AKS = "aks"
    ACI = "aci"
    GKE = "gke"
    CLOUD_RUN = "cloud_run"
    ECR = "ecr"
    ACR = "acr"
    GCR = "gcr"
    ARTIFACT_REGISTRY = "artifact_registry"


class ComplianceFramework(str, Enum):
    CIS_DOCKER = "cis_docker"
    CIS_KUBERNETES = "cis_kubernetes"
    NIST_800_190 = "nist_800_190"


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


# ── Cloud Models ─────────────────────────────────────────────────────────────

class CloudAccount(BaseModel):
    """Represents a cloud account / subscription / project."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: CloudProviderType
    account_id: str  # AWS account ID / Azure subscription ID / GCP project ID
    regions: List[str] = []
    role_arn: Optional[str] = None          # AWS cross-account
    tenant_id: Optional[str] = None         # Azure
    credential_profile: Optional[str] = None
    is_active: bool = True
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerImage(BaseModel):
    """A container image discovered in a cloud service."""
    image_uri: str
    tag: str = "latest"
    digest: Optional[str] = None
    registry: Optional[str] = None
    repository: Optional[str] = None
    cloud_provider: Optional[CloudProviderType] = None
    service_type: Optional[ServiceType] = None
    cluster_name: Optional[str] = None
    service_name: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None


class ContainerService(BaseModel):
    """A running container service (cluster, service, task)."""
    name: str
    service_type: ServiceType
    provider: CloudProviderType
    region: str
    account_id: str
    status: str = "ACTIVE"
    images: List[ContainerImage] = []
    metadata: Dict[str, Any] = {}


# ── Vulnerability Models ─────────────────────────────────────────────────────

class Vulnerability(BaseModel):
    """A single vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    category: str = ""
    type: str = "general"
    status: VulnStatus = VulnStatus.OPEN
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    remediation: str = ""
    priority_score: float = 0.0
    cvss_score: float = 0.0
    discovered_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    affected_products: List[str] = []
    references: List[str] = []
    cwe_ids: List[str] = []
    image: Optional[ContainerImage] = None
    cloud_account: Optional[str] = None
    compliance_controls: List[str] = []
    product: Optional[str] = None


class ScanResult(BaseModel):
    """Result of a vulnerability scan."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str = "dockerfile"
    target: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = []
    risk_score: float = 0.0
    risk_level: str = "LOW"
    cloud_account: Optional[str] = None
    service_type: Optional[ServiceType] = None
    metadata: Dict[str, Any] = {}


class RiskAssessment(BaseModel):
    """Risk assessment for a set of vulnerabilities."""
    total_score: float = 0.0
    average_score: float = 0.0
    risk_level: str = "LOW"
    vulnerability_count: int = 0
    severity_breakdown: Dict[str, int] = {}


class RemediationPlan(BaseModel):
    """AI-generated remediation plan."""
    immediate_actions: List[str] = []
    short_term_actions: List[str] = []
    long_term_actions: List[str] = []
    automated_fixes: List[Dict[str, Any]] = []
    manual_steps: List[str] = []
    estimated_effort: str = "Unknown"
    risk_reduction: float = 0.0
    ai_recommendations: str = ""


# ── Enterprise Models ────────────────────────────────────────────────────────

class AuditEvent(BaseModel):
    """An audit log entry."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user: str = "system"
    action: str
    target: str = ""
    result: str = "success"
    details: Dict[str, Any] = {}


class ComplianceControl(BaseModel):
    """A single compliance control check."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str = ""
    passed: bool = False
    severity: Severity = Severity.MEDIUM
    findings: List[str] = []
    remediation: str = ""


class ComplianceReport(BaseModel):
    """Compliance evaluation report."""
    framework: ComplianceFramework
    controls: List[ComplianceControl] = []
    total_controls: int = 0
    passed_controls: int = 0
    compliance_score: float = 0.0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Agent Models ─────────────────────────────────────────────────────────────

class AgentEvent(BaseModel):
    """An event emitted during an agent run."""
    type: str  # "response", "tool_call", "error", "complete"
    content: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_result: Optional[Any] = None
