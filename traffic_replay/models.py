from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import json
import uuid


@dataclass
class RequestRecord:
    id: str
    timestamp: float
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[Union[str, bytes]] = None
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[Union[str, bytes]] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    duration_ms: float = 0.0
    upstream_latency_ms: float = 0.0
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(self.body, bytes):
            data["body"] = self.body.hex()
            data["body_is_bytes"] = True
        if isinstance(self.response_body, bytes):
            data["response_body"] = self.response_body.hex()
            data["response_body_is_bytes"] = True
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestRecord":
        kwargs = data.copy()
        if kwargs.pop("body_is_bytes", False):
            kwargs["body"] = bytes.fromhex(kwargs["body"])
        if kwargs.pop("response_body_is_bytes", False):
            kwargs["response_body"] = bytes.fromhex(kwargs["response_body"])
        return cls(**kwargs)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "RequestRecord":
        return cls.from_dict(json.loads(json_str))


@dataclass
class SessionContext:
    session_id: str
    variables: Dict[str, Any] = field(default_factory=dict)
    request_sequence: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    last_updated: float = field(default_factory=lambda: datetime.now().timestamp())
    recording_env: str = "production"
    playback_env: str = "test"
    env_mappings: Dict[str, str] = field(default_factory=dict)

    def set_var(self, key: str, value: Any) -> None:
        self.variables[key] = value
        self.last_updated = datetime.now().timestamp()

    def get_var(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionContext":
        return cls(**data)


@dataclass
class ExtractionRule:
    name: str
    source: str
    selector: str
    variable_name: str
    description: Optional[str] = None


@dataclass
class MaskRule:
    name: str
    selector: str
    mask_type: str
    pattern: Optional[str] = None
    replacement: Optional[str] = None
    preserve_length: bool = True
    description: Optional[str] = None


@dataclass
class PlaybackReport:
    total_requests: int
    successful_requests: int
    failed_requests: int
    start_time: float
    end_time: float
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    max_latency_ms: float
    min_latency_ms: float
    timing_deviation_ms: List[float]
    errors: List[Dict[str, Any]]
