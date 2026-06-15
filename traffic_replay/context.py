import asyncio
import re
import json
import logging
from typing import Optional, Dict, Any, List, Union, Pattern
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    from jsonpath_ng import parse as jsonpath_parse
    JSONPATH_AVAILABLE = True
except ImportError:
    JSONPATH_AVAILABLE = False

from .models import RequestRecord, SessionContext, ExtractionRule

logger = logging.getLogger(__name__)


class ContextManager:
    def __init__(
        self,
        extraction_rules: Optional[List[ExtractionRule]] = None,
        env_mappings: Optional[Dict[str, str]] = None,
        enable_auto_extract: bool = True,
        variable_ttl_seconds: int = 3600,
    ):
        self.extraction_rules = extraction_rules or []
        self.env_mappings = env_mappings or {}
        self.enable_auto_extract = enable_auto_extract
        self.variable_ttl = variable_ttl_seconds

        self._contexts: Dict[str, SessionContext] = {}
        self._compiled_rules: Dict[str, Any] = {}

        self._compile_rules()

    def _compile_rules(self) -> None:
        for rule in self.extraction_rules:
            if rule.source == "json_body" and JSONPATH_AVAILABLE:
                try:
                    self._compiled_rules[rule.name] = jsonpath_parse(rule.selector)
                except Exception as e:
                    logger.warning(f"Failed to compile JSONPath {rule.selector}: {e}")
            elif rule.source in ("header", "query_param", "cookie"):
                self._compiled_rules[rule.name] = re.compile(rule.selector, re.IGNORECASE)
            elif rule.source == "regex_body":
                self._compiled_rules[rule.name] = re.compile(rule.selector)

    def create_context(
        self,
        session_id: str,
        recording_env: str = "production",
        playback_env: str = "test",
    ) -> SessionContext:
        context = SessionContext(
            session_id=session_id,
            recording_env=recording_env,
            playback_env=playback_env,
            env_mappings=self.env_mappings.copy(),
        )
        self._contexts[session_id] = context
        return context

    def get_context(self, session_id: str) -> Optional[SessionContext]:
        return self._contexts.get(session_id)

    def remove_context(self, session_id: str) -> None:
        if session_id in self._contexts:
            del self._contexts[session_id]

    def add_extraction_rule(self, rule: ExtractionRule) -> None:
        self.extraction_rules.append(rule)
        if rule.source == "json_body" and JSONPATH_AVAILABLE:
            self._compiled_rules[rule.name] = jsonpath_parse(rule.selector)
        elif rule.source in ("header", "query_param", "cookie"):
            self._compiled_rules[rule.name] = re.compile(rule.selector, re.IGNORECASE)
        elif rule.source == "regex_body":
            self._compiled_rules[rule.name] = re.compile(rule.selector)

    async def extract_variables(
        self,
        request: RequestRecord,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: bytes,
        context: SessionContext,
    ) -> Dict[str, Any]:
        extracted = {}

        if not 200 <= response_status < 300:
            return extracted

        for rule in self.extraction_rules:
            try:
                value = await self._extract_value(
                    rule, request, response_status, response_headers, response_body
                )
                if value is not None:
                    extracted[rule.variable_name] = value
                    context.set_var(rule.variable_name, value)
                    logger.debug(f"Extracted variable {rule.variable_name}: {value}")
            except Exception as e:
                logger.warning(f"Failed to extract {rule.name}: {e}")

        if self.enable_auto_extract:
            auto_extracted = await self._auto_extract(
                request, response_status, response_headers, response_body
            )
            for key, value in auto_extracted.items():
                if key not in extracted:
                    extracted[key] = value
                    context.set_var(key, value)

        context.request_sequence.append(request.id)
        return extracted

    async def _extract_value(
        self,
        rule: ExtractionRule,
        request: RequestRecord,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: bytes,
    ) -> Optional[Any]:
        compiled = self._compiled_rules.get(rule.name)

        if rule.source == "header":
            for h_key, h_value in response_headers.items():
                if compiled and compiled.match(h_key):
                    return h_value

        elif rule.source == "json_body" and JSONPATH_AVAILABLE:
            try:
                body_json = json.loads(response_body.decode("utf-8"))
                results = compiled.find(body_json)
                if results:
                    return results[0].value
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        elif rule.source == "regex_body":
            try:
                body_str = response_body.decode("utf-8")
                match = compiled.search(body_str)
                if match:
                    return match.group(1) if match.groups() else match.group(0)
            except UnicodeDecodeError:
                pass

        elif rule.source == "query_param":
            parsed = urlparse(request.url)
            params = parse_qs(parsed.query)
            for p_key, p_values in params.items():
                if compiled and compiled.match(p_key):
                    return p_values[0] if p_values else None

        elif rule.source == "request_body":
            if request.body:
                try:
                    body_str = request.body.decode("utf-8") if isinstance(request.body, bytes) else request.body
                    match = compiled.search(body_str)
                    if match:
                        return match.group(1) if match.groups() else match.group(0)
                except (UnicodeDecodeError, AttributeError):
                    pass

        elif rule.source == "response_json_path" and JSONPATH_AVAILABLE:
            try:
                body_json = json.loads(response_body.decode("utf-8"))
                results = compiled.find(body_json)
                if results:
                    return results[0].value
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        return None

    async def _auto_extract(
        self,
        request: RequestRecord,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: bytes,
    ) -> Dict[str, Any]:
        extracted = {}

        auth_headers = ["authorization", "x-auth-token", "x-access-token"]
        for h_key, h_value in response_headers.items():
            if h_key.lower() in auth_headers:
                token_name = h_key.lower().replace("-", "_")
                extracted[f"auto_{token_name}"] = h_value

        set_cookie = response_headers.get("Set-Cookie") or response_headers.get("set-cookie")
        if set_cookie:
            cookie_match = re.search(r'(\w+)=([^;]+)', set_cookie)
            if cookie_match:
                extracted[f"auto_cookie_{cookie_match.group(1)}"] = cookie_match.group(2)

        try:
            body_json = json.loads(response_body.decode("utf-8"))
            if isinstance(body_json, dict):
                token_fields = ["token", "accessToken", "access_token", "id", "uuid"]
                for field in token_fields:
                    if field in body_json:
                        extracted[f"auto_{field}"] = body_json[field]
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        return extracted

    async def apply_context(
        self, record: RequestRecord, context: SessionContext
    ) -> RequestRecord:
        if not context.variables:
            return record

        new_headers = dict(record.headers)
        new_body = record.body
        new_url = record.url

        for key, value in context.variables.items():
            if not isinstance(value, (str, int, float)):
                continue

            str_value = str(value)
            placeholder = f"{{{{{key}}}}}"

            for h_key, h_value in list(new_headers.items()):
                if isinstance(h_value, str) and placeholder in h_value:
                    new_headers[h_key] = h_value.replace(placeholder, str_value)

            if isinstance(new_body, bytes):
                try:
                    body_str = new_body.decode("utf-8")
                    if placeholder in body_str:
                        body_str = body_str.replace(placeholder, str_value)
                        new_body = body_str.encode("utf-8")
                except UnicodeDecodeError:
                    pass
            elif isinstance(new_body, str) and placeholder in new_body:
                new_body = new_body.replace(placeholder, str_value)

            if placeholder in new_url:
                new_url = new_url.replace(placeholder, str_value)

        new_url = self._apply_env_mapping(new_url, context)
        new_headers = self._apply_env_mapping_to_headers(new_headers, context)

        return RequestRecord(
            id=record.id,
            timestamp=record.timestamp,
            method=record.method,
            url=new_url,
            headers=new_headers,
            body=new_body,
            response_status=record.response_status,
            response_headers=record.response_headers,
            response_body=record.response_body,
            session_id=record.session_id,
            trace_id=record.trace_id,
            duration_ms=record.duration_ms,
            upstream_latency_ms=record.upstream_latency_ms,
            tags=record.tags,
        )

    def _apply_env_mapping(self, url: str, context: SessionContext) -> str:
        if not context.env_mappings:
            return url

        parsed = urlparse(url)
        netloc = parsed.netloc

        for old, new in context.env_mappings.items():
            if old in netloc:
                netloc = netloc.replace(old, new)

        return urlunparse(parsed._replace(netloc=netloc))

    def _apply_env_mapping_to_headers(
        self, headers: Dict[str, str], context: SessionContext
    ) -> Dict[str, str]:
        if not context.env_mappings:
            return headers

        new_headers = dict(headers)
        host_key = None
        for k in new_headers:
            if k.lower() == "host":
                host_key = k
                break

        if host_key and host_key in new_headers:
            host_value = new_headers[host_key]
            for old, new in context.env_mappings.items():
                if old in host_value:
                    new_headers[host_key] = host_value.replace(old, new)

        return new_headers

    def analyze_dependencies(
        self, records: List[RequestRecord]
    ) -> Dict[str, List[str]]:
        dependencies: Dict[str, List[str]] = {}
        var_producers: Dict[str, str] = {}

        for record in records:
            deps = set()

            if record.body:
                try:
                    body_str = record.body.decode("utf-8") if isinstance(record.body, bytes) else record.body
                    placeholders = re.findall(r'\{\{(\w+)\}\}', body_str)
                    for var in placeholders:
                        if var in var_producers:
                            deps.add(var_producers[var])
                except (UnicodeDecodeError, AttributeError):
                    pass

            for h_key, h_value in record.headers.items():
                if isinstance(h_value, str):
                    placeholders = re.findall(r'\{\{(\w+)\}\}', h_value)
                    for var in placeholders:
                        if var in var_producers:
                            deps.add(var_producers[var])

            dependencies[record.id] = list(deps)

            for rule in self.extraction_rules:
                var_producers[rule.variable_name] = record.id

        return dependencies

    def get_variable_names(self) -> List[str]:
        return [r.variable_name for r in self.extraction_rules]
