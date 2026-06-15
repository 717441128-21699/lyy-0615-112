import os
import yaml
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from .models import MaskRule, ExtractionRule


@dataclass
class RecorderConfig:
    target_url: str = "http://localhost:8080"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    mode: str = "tap"
    sample_rate: float = 1.0
    capture_response: bool = True
    max_body_size: int = 10 * 1024 * 1024
    timeout_ms: int = 30000
    num_workers: int = 10


@dataclass
class StorageConfig:
    base_dir: str = "./recordings"
    batch_size: int = 100
    flush_interval_ms: int = 500
    compress: bool = True
    max_memory_mb: int = 100


@dataclass
class PlayerConfig:
    target_url: str = "http://localhost:8080"
    mode: str = "precise"
    speed_factor: float = 1.0
    max_concurrent: int = 100
    timeout_ms: int = 30000
    retry_count: int = 0
    retry_delay_ms: int = 1000
    ignore_ssl: bool = False
    loop_count: int = 1


@dataclass
class MaskingConfig:
    enabled: bool = True
    preserve_structure: bool = True
    default_mask_char: str = "*"
    hash_algorithm: str = "sha256"
    hash_salt: Optional[str] = None
    locale: str = "zh_CN"
    rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ContextConfig:
    enabled: bool = True
    enable_auto_extract: bool = True
    variable_ttl_seconds: int = 3600
    env_mappings: Dict[str, str] = field(default_factory=dict)
    extraction_rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AppConfig:
    recorder: RecorderConfig = field(default_factory=RecorderConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    player: PlayerConfig = field(default_factory=PlayerConfig)
    masking: MaskingConfig = field(default_factory=MaskingConfig)
    context: ContextConfig = field(default_factory=ContextConfig)
    log_level: str = "INFO"
    log_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recorder": asdict(self.recorder),
            "storage": asdict(self.storage),
            "player": asdict(self.player),
            "masking": asdict(self.masking),
            "context": asdict(self.context),
            "log_level": self.log_level,
            "log_file": self.log_file,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppConfig":
        return cls(
            recorder=RecorderConfig(**data.get("recorder", {})),
            storage=StorageConfig(**data.get("storage", {})),
            player=PlayerConfig(**data.get("player", {})),
            masking=MaskingConfig(**data.get("masking", {})),
            context=ContextConfig(**data.get("context", {})),
            log_level=data.get("log_level", "INFO"),
            log_file=data.get("log_file"),
        )


class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config.yaml"
        self._config: Optional[AppConfig] = None

    def load(self) -> AppConfig:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                if self.config_path.endswith(".yaml") or self.config_path.endswith(".yml"):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            self._config = AppConfig.from_dict(data)
        else:
            self._config = AppConfig()
        return self._config

    def save(self, config: Optional[AppConfig] = None) -> None:
        config = config or self._config or AppConfig()
        data = config.to_dict()
        os.makedirs(os.path.dirname(os.path.abspath(self.config_path)) or ".", exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            if self.config_path.endswith(".yaml") or self.config_path.endswith(".yml"):
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
            else:
                json.dump(data, f, indent=2, ensure_ascii=False)

    @property
    def config(self) -> AppConfig:
        if self._config is None:
            self.load()
        return self._config

    def get_mask_rules(self) -> List[MaskRule]:
        if not self.config.masking.enabled:
            return []
        return [
            MaskRule(
                name=rule["name"],
                selector=rule["selector"],
                mask_type=rule.get("mask_type", "mask"),
                pattern=rule.get("pattern"),
                replacement=rule.get("replacement"),
                preserve_length=rule.get("preserve_length", True),
                description=rule.get("description"),
            )
            for rule in self.config.masking.rules
        ]

    def get_extraction_rules(self) -> List[ExtractionRule]:
        if not self.config.context.enabled:
            return []
        return [
            ExtractionRule(
                name=rule["name"],
                source=rule["source"],
                selector=rule["selector"],
                variable_name=rule["variable_name"],
                description=rule.get("description"),
            )
            for rule in self.config.context.extraction_rules
        ]

    def create_default_config(self) -> AppConfig:
        config = AppConfig()
        config.masking.rules = [
            {
                "name": "mask_password",
                "selector": "password",
                "mask_type": "hash",
                "preserve_length": False,
                "description": "Hash all password fields",
            },
            {
                "name": "mask_phone",
                "selector": "phone",
                "mask_type": "mask",
                "pattern": r'1[3-9]\d{9}',
                "preserve_length": True,
                "description": "Mask phone numbers",
            },
            {
                "name": "mask_email",
                "selector": "email",
                "mask_type": "mask",
                "preserve_length": True,
                "description": "Mask email addresses",
            },
        ]
        config.context.extraction_rules = [
            {
                "name": "extract_auth_token",
                "source": "header",
                "selector": "X-Auth-Token",
                "variable_name": "auth_token",
                "description": "Extract auth token from response headers",
            },
            {
                "name": "extract_user_id",
                "source": "json_body",
                "selector": "$.data.user_id",
                "variable_name": "user_id",
                "description": "Extract user_id from JSON response",
            },
        ]
        config.context.env_mappings = {
            "prod.example.com": "test.example.com",
        }
        self._config = config
        return config
