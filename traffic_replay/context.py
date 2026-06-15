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

        auth_headers = ["authorization", "x-auth-token", "x-access-token",
                        "x_security_token", "authentication"]
        for h_key, h_value in response_headers.items():
            if h_key.lower() in auth_headers:
                token_name = h_key.lower().replace("-", "_")
                clean_value = h_value
                if "bearer " in h_value.lower():
                    clean_value = h_value[7:] if len(h_value) > 7 else h_value
                extracted[f"auto_{token_name}"] = clean_value
                if "token" not in extracted:
                    extracted["auth_token"] = clean_value

        set_cookie = response_headers.get("Set-Cookie") or response_headers.get("set-cookie")
        if set_cookie:
            cookie_match = re.search(r'(\w+)=([^;]+)', set_cookie)
            if cookie_match:
                cookie_name = cookie_match.group(1).lower()
                cookie_value = cookie_match.group(2)
                extracted[f"auto_cookie_{cookie_name}"] = cookie_value
                if "session" in cookie_name or "token" in cookie_name:
                    if "auth_token" not in extracted:
                        extracted["auth_token"] = cookie_value

        self._recursive_extract_json(None, response_body, extracted)

        return extracted

    def _recursive_extract_json(
        self, parent_key: Optional[str], data: Any, extracted: Dict[str, Any]
    ) -> None:
        if isinstance(data, (bytes, bytearray)):
            try:
                body_json = json.loads(data.decode("utf-8"))
                self._recursive_extract_json("root", body_json, extracted)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            return

        priority_token_fields = {
            "token", "access_token", "accesstoken", "access_token",
            "auth_token", "authtoken", "jwt_token", "jwt",
            "api_token", "apitoken", "session_token", "sessiontoken",
        }

        priority_id_fields = {
            "user_id", "userid", "useruuid", "user_uuid",
            "uid", "account_id", "accountid", "member_id", "memberid",
        }

        other_id_fields = {
            "id", "uuid", "order_id", "orderid",
            "product_id", "productid", "biz_id", "bizid",
        }

        if isinstance(data, dict):
            for key, value in data.items():
                if not isinstance(key, str):
                    continue

                key_lower = key.lower().replace("-", "_")
                key_clean = key_lower.replace("_", "")

                if isinstance(value, str):
                    if key_lower in priority_token_fields or key_clean in priority_token_fields:
                        if "auth_token" not in extracted:
                            extracted["auth_token"] = value
                        if f"auto_{key_lower}" not in extracted:
                            extracted[f"auto_{key_lower}"] = value

                    elif key_lower in priority_id_fields or key_clean in priority_id_fields:
                        if "user_id" not in extracted:
                            extracted["user_id"] = value
                        if f"auto_{key_lower}" not in extracted:
                            extracted[f"auto_{key_lower}"] = value

                    elif key_lower in other_id_fields or key_clean in other_id_fields:
                        if parent_key == "data" or parent_key == "result":
                            if key_lower == "id" and "user_id" not in extracted:
                                extracted["auto_id"] = value
                            else:
                                extracted[f"auto_{key_lower}"] = value
                        else:
                            extracted[f"auto_{key_lower}"] = value

                if isinstance(value, (dict, list)):
                    self._recursive_extract_json(key_lower, value, extracted)

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._recursive_extract_json(parent_key, item, extracted)

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

        new_headers = self._auto_inject_headers(new_headers, context)
        new_body = self._auto_inject_body(new_body, context)
        new_headers = self._auto_inject_cookie(new_headers, context)
        new_url = self._auto_inject_url_query(new_url, context)

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

    def _auto_inject_headers(
        self, headers: Dict[str, str], context: SessionContext
    ) -> Dict[str, str]:
        if not context.variables:
            return headers

        new_headers = dict(headers)
        vars_lower = {k.lower(): v for k, v in context.variables.items()}

        token_value = None
        for var_name in ["auth_token", "auto_auth_token", "access_token", "auto_access_token",
                         "auto_x_auth_token", "auto_token", "token", "auto_authorization"]:
            if var_name in vars_lower:
                token_value = str(vars_lower[var_name])
                break

        if token_value:
            has_auth = False
            has_x_auth = False
            has_token = False

            for h_key in list(new_headers.keys()):
                h_lower = h_key.lower()
                if h_lower == "authorization":
                    if token_value.startswith("Bearer "):
                        new_headers[h_key] = token_value
                    else:
                        new_headers[h_key] = f"Bearer {token_value}"
                    has_auth = True
                elif h_lower == "x-auth-token":
                    new_headers[h_key] = token_value
                    has_x_auth = True
                elif h_lower == "x-access-token":
                    new_headers[h_key] = token_value
                elif h_lower == "token":
                    new_headers[h_key] = token_value
                    has_token = True

            if not has_x_auth and not has_auth and not has_token:
                new_headers["X-Auth-Token"] = token_value

        return new_headers

    def _auto_inject_body(
        self, body: Optional[Union[str, bytes]], context: SessionContext
    ) -> Optional[Union[str, bytes]]:
        if body is None or not context.variables:
            return body

        is_bytes = isinstance(body, bytes)
        if is_bytes:
            try:
                body_str = body.decode("utf-8")
            except UnicodeDecodeError:
                return body
        else:
            body_str = body

        if self._is_json(body_str):
            try:
                data = json.loads(body_str)
                data = self._auto_inject_json(data, context)
                result = json.dumps(data, ensure_ascii=False)
                return result.encode("utf-8") if is_bytes else result
            except (json.JSONDecodeError, ValueError):
                pass

        return body

    def _auto_inject_json(self, data: Any, context: SessionContext) -> Any:
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                key_lower = key.lower()
                injected = False

                for var_name, var_value in context.variables.items():
                    var_lower = var_name.lower().replace("auto_", "")
                    if var_lower in key_lower and isinstance(var_value, str):
                        if key_lower in ("token", "access_token", "authtoken",
                                         "user_id", "userid", "uuid"):
                            result[key] = var_value
                            injected = True
                            break

                if not injected:
                    result[key] = self._auto_inject_json(value, context)
            return result
        elif isinstance(data, list):
            return [self._auto_inject_json(item, context) for item in data]
        else:
            return data

    def _auto_inject_url_query(
        self, url: str, context: SessionContext
    ) -> str:
        if not url or not context.variables or "?" not in url:
            return url

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        try:
            parsed = urlparse(url)
            if not parsed.query:
                return url
        except Exception:
            return url

        vars_lower = {k.lower(): v for k, v in context.variables.items()}

        token_value = None
        for var_name in ["auth_token", "auto_auth_token", "access_token", "auto_access_token",
                         "auto_x_auth_token", "auto_token", "token", "auto_authorization"]:
            if var_name in vars_lower:
                token_value = str(vars_lower[var_name])
                break

        user_id_value = None
        for var_name in ["user_id", "auto_user_id", "uid", "auto_id", "auto_uuid"]:
            if var_name in vars_lower:
                user_id_value = str(vars_lower[var_name])
                break

        if not token_value and not user_id_value:
            return url

        try:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return url

        modified = False
        sensitive_token_keys = {"token", "auth", "access_token", "accesstoken",
                                "jwt", "auth_token", "authtoken", "session_token",
                                "sessiontoken", "apikey", "api_key", "api-token"}

        sensitive_id_keys = {"user_id", "userid", "uid", "account_id", "accountid"}

        for q_key in list(query_params.keys()):
            q_lower = q_key.lower().replace("-", "_")

            if token_value and q_lower in sensitive_token_keys:
                query_params[q_key] = [token_value]
                modified = True
            elif user_id_value and q_lower in sensitive_id_keys:
                query_params[q_key] = [user_id_value]
                modified = True

        if not modified:
            return url

        try:
            new_query = urlencode(query_params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    def _auto_inject_cookie(
        self, headers: Dict[str, str], context: SessionContext
    ) -> Dict[str, str]:
        if not headers or not context.variables:
            return headers

        vars_lower = {k.lower(): v for k, v in context.variables.items()}

        token_value = None
        for var_name in ["auth_token", "auto_auth_token", "access_token", "auto_access_token",
                         "auto_x_auth_token", "auto_token", "token"]:
            if var_name in vars_lower:
                token_value = str(vars_lower[var_name])
                break

        if not token_value:
            return headers

        new_headers = dict(headers)

        for h_key in list(new_headers.keys()):
            if h_key.lower() != "cookie":
                continue

            cookie_str = new_headers[h_key]
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            new_parts = []
            modified = False

            token_cookie_keywords = ("token", "session", "sid", "auth",
                                      "jwt", "access", "cookie")

            for part in cookie_parts:
                if "=" not in part:
                    new_parts.append(part)
                    continue
                try:
                    c_name, c_val = part.split("=", 1)
                    c_lower = c_name.strip().lower().replace("-", "_")
                    is_auth_cookie = False
                    if c_lower == "token" or c_lower == "session" or c_lower == "auth":
                        is_auth_cookie = True
                    else:
                        for kw in token_cookie_keywords:
                            if kw in c_lower:
                                is_auth_cookie = True
                                break
                    if is_auth_cookie and len(c_val) > 3:
                        new_parts.append(f"{c_name.strip()}={token_value}")
                        modified = True
                    else:
                        new_parts.append(part)
                except (ValueError, IndexError):
                    new_parts.append(part)

            if modified:
                new_headers[h_key] = "; ".join(new_parts)
                break

        return new_headers

    def _is_json(self, s: str) -> bool:
        s = s.strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))

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
