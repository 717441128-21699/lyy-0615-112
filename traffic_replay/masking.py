import re
import json
import hashlib
import logging
import random
import string
from typing import Optional, Dict, Any, List, Union, Pattern
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from dataclasses import dataclass

try:
    from jsonpath_ng import parse as jsonpath_parse
    JSONPATH_AVAILABLE = True
except ImportError:
    JSONPATH_AVAILABLE = False

try:
    from faker import Faker
    FAKER_AVAILABLE = True
except ImportError:
    FAKER_AVAILABLE = False

from .models import RequestRecord, MaskRule

logger = logging.getLogger(__name__)


class MaskType:
    MASK = "mask"
    HASH = "hash"
    REPLACE = "replace"
    REDACT = "redact"
    TRUNCATE = "truncate"
    PSEUDONYMIZE = "pseudonymize"


class MaskingEngine:
    def __init__(
        self,
        rules: Optional[List[MaskRule]] = None,
        preserve_structure: bool = True,
        default_mask_char: str = "*",
        hash_algorithm: str = "sha256",
        hash_salt: Optional[str] = None,
        locale: str = "zh_CN",
    ):
        self.rules = rules or []
        self.preserve_structure = preserve_structure
        self.default_mask_char = default_mask_char
        self.hash_algorithm = hash_algorithm
        self.hash_salt = hash_salt or b"traffic_replay_salt"
        self.locale = locale

        self._compiled_jsonpath: Dict[str, Any] = {}
        self._compiled_regex: Dict[str, Pattern] = {}
        self._faker = Faker(locale) if FAKER_AVAILABLE else None

        self._compile_rules()
        self._init_builtin_patterns()

    def _compile_rules(self) -> None:
        for rule in self.rules:
            if rule.selector.startswith("$.") or rule.selector.startswith("$["):
                if JSONPATH_AVAILABLE:
                    try:
                        self._compiled_jsonpath[rule.name] = jsonpath_parse(rule.selector)
                    except Exception as e:
                        logger.warning(f"Failed to compile JSONPath {rule.selector}: {e}")
            elif rule.pattern:
                self._compiled_regex[rule.name] = re.compile(rule.pattern)

    def _init_builtin_patterns(self) -> None:
        self._builtin_patterns = {
            "phone": re.compile(r'1[3-9]\d{9}'),
            "id_card": re.compile(r'\d{17}[\dXx]'),
            "email": re.compile(r'[\w.-]+@[\w.-]+\.\w+'),
            "bank_card": re.compile(r'\d{16,19}'),
            "password": re.compile(r'(?i)password["\s:=]+["\']?([^\s"\']+)'),
            "token": re.compile(r'(?i)(token|authorization|auth|secret)["\s:=]+["\']?([^\s"\']+)'),
            "cookie": re.compile(r'(?i)(session|cookie)["\s:=]+["\']?([^\s"\']+)'),
            "ipv4": re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
            "ipv6": re.compile(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
        }

    def add_rule(self, rule: MaskRule) -> None:
        self.rules.append(rule)
        if rule.selector.startswith("$.") or rule.selector.startswith("$["):
            if JSONPATH_AVAILABLE:
                self._compiled_jsonpath[rule.name] = jsonpath_parse(rule.selector)
        elif rule.pattern:
            self._compiled_regex[rule.name] = re.compile(rule.pattern)

    async def mask_record(self, record: RequestRecord) -> RequestRecord:
        new_headers = await self._mask_headers(record.headers)
        new_body = await self._mask_body(record.body)
        new_url = await self._mask_url(record.url)
        new_response_body = await self._mask_body(record.response_body)
        new_response_headers = await self._mask_headers(record.response_headers)

        return RequestRecord(
            id=record.id,
            timestamp=record.timestamp,
            method=record.method,
            url=new_url,
            headers=new_headers,
            body=new_body,
            response_status=record.response_status,
            response_headers=new_response_headers,
            response_body=new_response_body,
            session_id=await self._mask_session_id(record.session_id),
            trace_id=record.trace_id,
            duration_ms=record.duration_ms,
            upstream_latency_ms=record.upstream_latency_ms,
            tags=await self._mask_tags(record.tags),
        )

    async def mask_data(self, data: Any, selector: Optional[str] = None) -> Any:
        if selector:
            return await self._apply_selector(data, selector)
        return await self._auto_mask(data)

    async def _mask_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        if not headers:
            return headers

        masked = dict(headers)

        sensitive_headers = [
            "authorization", "cookie", "set-cookie", "x-auth-token",
            "x-api-key", "x-secret-key", "password", "token",
            "proxy-authorization", "www-authenticate",
        ]

        for key in list(masked.keys()):
            key_lower = key.lower()

            for pattern_name, pattern in self._builtin_patterns.items():
                if pattern_name in key_lower:
                    masked[key] = self._apply_mask_to_value(masked[key], MaskType.MASK, preserve_length=True)
                    break

            for rule in self.rules:
                if hasattr(rule, 'source') and rule.source == "header" and rule.selector.lower() in key_lower:
                    masked[key] = self._apply_mask_to_value(
                        masked[key], rule.mask_type, rule.preserve_length, rule.replacement
                    )
                    break

            if key_lower in sensitive_headers:
                masked[key] = self._apply_mask_to_value(masked[key], MaskType.MASK, preserve_length=True)

        return masked

    async def _mask_body(self, body: Optional[Union[str, bytes]]) -> Optional[Union[str, bytes]]:
        if body is None:
            return body

        is_bytes = isinstance(body, bytes)
        if is_bytes:
            try:
                body_str = body.decode("utf-8")
            except UnicodeDecodeError:
                return body
        else:
            body_str = body

        if not body_str:
            return body

        if self._is_json(body_str):
            try:
                data = json.loads(body_str)
                masked_data = await self._mask_json(data)
                result = json.dumps(masked_data, ensure_ascii=False)
                return result.encode("utf-8") if is_bytes else result
            except json.JSONDecodeError:
                pass

        if self._is_form_data(body_str):
            masked_str = await self._mask_form_data(body_str)
            return masked_str.encode("utf-8") if is_bytes else masked_str

        masked_str = await self._mask_text(body_str)
        return masked_str.encode("utf-8") if is_bytes else masked_str

    async def _mask_url(self, url: str) -> str:
        if not url:
            return url

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        masked_params = {}
        for key, values in query_params.items():
            masked_values = []
            for value in values:
                masked_value = value
                for rule in self.rules:
                    if hasattr(rule, 'source') and rule.source == "query_param" and rule.selector.lower() in key.lower():
                        masked_value = self._apply_mask_to_value(
                            value, rule.mask_type, rule.preserve_length, rule.replacement
                        )
                        break
                masked_values.append(masked_value)
            masked_params[key] = masked_values

        new_query = urlencode(masked_params, doseq=True)

        return urlunparse(parsed._replace(query=new_query))

    async def _mask_json(self, data: Any) -> Any:
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                for rule in self.rules:
                    if rule.mask_type == MaskType.REDACT and rule.selector.lower() in key.lower():
                        continue
                    if rule.selector.lower() in key.lower():
                        value = self._apply_mask_to_value(
                            str(value), rule.mask_type, rule.preserve_length, rule.replacement
                        )
                        break
                else:
                    for pattern_name, pattern in self._builtin_patterns.items():
                        if pattern_name in key.lower():
                            value = self._apply_mask_to_value(
                                str(value), MaskType.MASK, preserve_length=True
                            )
                            break
                result[key] = await self._mask_json(value)
            return result
        elif isinstance(data, list):
            return [await self._mask_json(item) for item in data]
        elif isinstance(data, str):
            return await self._mask_text(data)
        else:
            return data

    async def _mask_form_data(self, data: str) -> str:
        params = parse_qs(data)
        masked_params = {}
        for key, values in params.items():
            masked_values = []
            for value in values:
                masked_value = value
                for rule in self.rules:
                    if hasattr(rule, 'source') and rule.source == "form_field" and rule.selector.lower() in key.lower():
                        masked_value = self._apply_mask_to_value(
                            value, rule.mask_type, rule.preserve_length, rule.replacement
                        )
                        break
                else:
                    for pattern_name, pattern in self._builtin_patterns.items():
                        if pattern_name in key.lower():
                            masked_value = self._apply_mask_to_value(
                                value, MaskType.MASK, preserve_length=True
                            )
                            break
                masked_values.append(masked_value)
            masked_params[key] = masked_values
        return urlencode(masked_params, doseq=True)

    async def _mask_text(self, text: str) -> str:
        result = text
        for rule in self.rules:
            if rule.name in self._compiled_regex:
                pattern = self._compiled_regex[rule.name]
                def replacer(m):
                    return self._apply_mask_to_value(
                        m.group(0), rule.mask_type, rule.preserve_length, rule.replacement
                    )
                result = pattern.sub(replacer, result)

        for pattern_name, pattern in self._builtin_patterns.items():
            def replacer(m):
                return self._apply_mask_to_value(
                    m.group(0), MaskType.MASK, preserve_length=True
                )
            result = pattern.sub(replacer, result)

        return result

    def _apply_mask_to_value(
        self,
        value: str,
        mask_type: str,
        preserve_length: bool = True,
        replacement: Optional[str] = None,
    ) -> str:
        if not value:
            return value

        if mask_type == MaskType.MASK:
            return self._mask_string(value, preserve_length)
        elif mask_type == MaskType.HASH:
            return self._hash_string(value)
        elif mask_type == MaskType.REPLACE:
            return replacement or self._faker_value(value)
        elif mask_type == MaskType.REDACT:
            return "[REDACTED]"
        elif mask_type == MaskType.TRUNCATE:
            return value[:4] + "..." if len(value) > 4 else value
        elif mask_type == MaskType.PSEUDONYMIZE:
            return self._faker_value(value)
        else:
            return self._mask_string(value, preserve_length)

    def _mask_string(self, s: str, preserve_length: bool) -> str:
        if not s:
            return s

        if preserve_length:
            n = len(s)
            if n <= 2:
                return self.default_mask_char * n
            elif n <= 6:
                return s[0] + self.default_mask_char * (n - 2) + s[-1]
            elif "@" in s and "." in s:
                parts = s.split("@")
                if len(parts) == 2:
                    local, domain = parts
                    if len(local) <= 2:
                        masked_local = local[0] + self.default_mask_char * (len(local) - 2) + local[-1]
                    else:
                        masked_local = self.default_mask_char * len(local)
                    return f"{masked_local}@{domain}"

            mid_start = n // 3
            mid_end = 2 * n // 3
            return s[:mid_start] + self.default_mask_char * (mid_end - mid_start) + s[mid_end:]
        else:
            return self.default_mask_char * min(len(s), 8)

    def _hash_string(self, s: str) -> str:
        if not s:
            return s

        hash_obj = hashlib.new(self.hash_algorithm)
        if isinstance(self.hash_salt, str):
            hash_obj.update(self.hash_salt.encode("utf-8"))
        else:
            hash_obj.update(self.hash_salt)
        hash_obj.update(s.encode("utf-8"))
        return hash_obj.hexdigest()[:16]

    def _faker_value(self, original: str) -> str:
        if not self._faker:
            return self._mask_string(original, True)

        if self._builtin_patterns["phone"].match(original):
            return self._faker.phone_number()
        elif self._builtin_patterns["email"].match(original):
            return self._faker.email()
        elif self._builtin_patterns["id_card"].match(original):
            return self._faker.ssn()
        elif self._builtin_patterns["ipv4"].match(original):
            return self._faker.ipv4()
        else:
            return self._faker.word()

    def _mask_session_id(self, session_id: Optional[str]) -> Optional[str]:
        if not session_id:
            return session_id
        return self._hash_string(session_id)

    async def _mask_tags(self, tags: Dict[str, str]) -> Dict[str, str]:
        if not tags:
            return tags

        masked = dict(tags)
        for key in list(masked.keys()):
            key_lower = key.lower()
            for pattern_name in self._builtin_patterns.keys():
                if pattern_name in key_lower:
                    masked[key] = self._apply_mask_to_value(
                        masked[key], MaskType.MASK, preserve_length=True
                    )
                    break
        return masked

    async def _apply_selector(self, data: Any, selector: str) -> Any:
        if not JSONPATH_AVAILABLE:
            return data

        try:
            jsonpath_expr = jsonpath_parse(selector)
            matches = jsonpath_expr.find(data)
            for match in matches:
                parent = data
                path_parts = str(match.full_path).split(".")
                for part in path_parts[:-1]:
                    if isinstance(parent, dict):
                        parent = parent.get(part)
                    elif isinstance(parent, list):
                        parent = parent[int(part.strip("[]"))]
                last_part = path_parts[-1]
                if isinstance(match.value, str):
                    if isinstance(parent, dict):
                        parent[last_part] = self._apply_mask_to_value(
                            match.value, MaskType.MASK, True
                        )
                    elif isinstance(parent, list):
                        idx = int(last_part.strip("[]"))
                        parent[idx] = self._apply_mask_to_value(
                            match.value, MaskType.MASK, True
                        )
            return data
        except Exception as e:
            logger.warning(f"Failed to apply selector {selector}: {e}")
            return data

    async def _auto_mask(self, data: Any) -> Any:
        if isinstance(data, dict):
            return await self._mask_json(data)
        elif isinstance(data, str):
            return await self._mask_text(data)
        elif isinstance(data, list):
            return [await self._auto_mask(item) for item in data]
        else:
            return data

    def _is_json(self, s: str) -> bool:
        s = s.strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))

    def _is_form_data(self, s: str) -> bool:
        return "=" in s and "&" in s

    def validate_masked_request(
        self, original: Any, masked: Any
    ) -> bool:
        try:
            if isinstance(original, dict):
                json.dumps(masked)
                return True
            elif isinstance(original, str):
                if self._is_json(original):
                    json.loads(masked)
                return True
            return True
        except Exception:
            return False
