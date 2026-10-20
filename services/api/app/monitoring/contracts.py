"""Strict configuration contracts; source credentials never enter public config."""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

WAF_LOG_GROUP_PREFIX = "aws-waf-logs-"
#: Where a monitor records its optional origin (ALB metrics) source. It lives in
#: ``context`` beside ``repository_source_id`` rather than in ``source_ids``, because
#: collection binds exactly one primary source and asserts it; an origin source is
#: supplementary, so its absence or failure must never change how the WAF day collects.
ORIGIN_SOURCE_KEY = "origin_source_id"
_LOG_GROUP_ARN = re.compile(
    r"arn:aws(?:-[a-z]+)*:logs:(?P<region>[a-z]{2}(?:-[a-z]+)+-\d):(?P<account>\d{12}):"
    r"log-group:(?P<group>[.\-_/#A-Za-z0-9]{1,512})(?::\*)?"
)
#: An Application Load Balancer. Network Load Balancers are refused on purpose: their
#: metrics describe TCP flows and carry no HTTP response codes, which are the point of
#: this source.
_LOAD_BALANCER_ARN = re.compile(
    r"arn:aws(?:-[a-z]+)*:elasticloadbalancing:(?P<region>[a-z]{2}(?:-[a-z]+)+-\d):"
    r"(?P<account>\d{12}):loadbalancer/(?P<resource>app/[A-Za-z0-9-]{1,32}/[0-9a-f]{16})"
)


def parse_log_group_arn(arn: str, *, require_waf_prefix: bool = True) -> tuple[str, str, str]:
    """Split a CloudWatch Logs log-group ARN into (region, account, group name).

    The console copies the ARN with a trailing ``:*``; it is accepted and dropped.
    """
    match = _LOG_GROUP_ARN.fullmatch(arn.strip())
    if match is None:
        raise ValueError("expected arn:aws:logs:<region>:<account>:log-group:<name>")
    if require_waf_prefix and not match["group"].startswith(WAF_LOG_GROUP_PREFIX):
        raise ValueError("AWS WAF log group names start with aws-waf-logs-")
    return match["region"], match["account"], match["group"]


def parse_load_balancer_arn(arn: str) -> tuple[str, str, str]:
    """Split an Application Load Balancer ARN into (region, account, ``app/name/id``)."""
    value = arn.strip()
    match = _LOAD_BALANCER_ARN.fullmatch(value)
    if match is None:
        if ":loadbalancer/net/" in value:
            raise ValueError(
                "Network Load Balancers report TCP flows, not HTTP response codes; "
                "use an Application Load Balancer"
            )
        raise ValueError(
            "expected arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/app/<name>/<id>"
        )
    return match["region"], match["account"], match["resource"]


class RouteBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    path: str = Field(min_length=1, max_length=300, pattern=r"^/[A-Za-z0-9_{}./-]*$")

    @field_validator("path")
    @classmethod
    def safe_template(cls, value: str) -> str:
        import re

        if any(p in {".", ".."} for p in value.split("/")):
            raise ValueError("invalid route template")
        if "{" in re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "", value):
            raise ValueError("invalid route template")
        return value


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    routes: list[RouteBinding] = Field(default_factory=list, max_length=200)
    region: str | None = Field(
        default=None, pattern=r"^(us|eu|ap|ca|sa|af|me|il|mx)-(?:[a-z]+-)?[a-z]+-\d$"
    )
    log_group: str | None = Field(
        default=None, min_length=1, max_length=512, pattern=r"^[.\-_/#A-Za-z0-9]+$"
    )
    account_id: str | None = Field(default=None, pattern=r"^\d{12}$")
    #: ``app/<name>/<id>`` of an Application Load Balancer: the ``LoadBalancer``
    #: dimension its CloudWatch metrics are published under.
    load_balancer: str | None = Field(
        default=None, max_length=80, pattern=r"^app/[A-Za-z0-9-]{1,32}/[0-9a-f]{16}$"
    )
    repository: str | None = Field(
        default=None, max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
    )
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    # Branch or tag read on demand through the GitHub MCP server.
    ref: str | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$")
    paths: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str | None) -> str | None:
        if value is not None and (
            value.startswith(("/", "-")) or ".." in value or value.endswith((".lock", "/"))
        ):
            raise ValueError("invalid Git ref")
        return value

    @field_validator("paths")
    @classmethod
    def exact_paths(cls, paths: list[str]) -> list[str]:
        import re

        for path in paths:
            if (
                len(path) > 240
                or not re.fullmatch(r"[A-Za-z0-9_./-]+", path)
                or path.startswith("/")
                or any(p in {"", ".", ".."} for p in path.split("/"))
                or not path.endswith((".py", ".ts", ".js"))
            ):
                raise ValueError("only explicit relative source-file paths are allowed")
        return list(dict.fromkeys(paths))


class SourceCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key_id: SecretStr | None = Field(default=None, max_length=128)
    secret_access_key: SecretStr | None = Field(default=None, max_length=256)
    session_token: SecretStr | None = Field(default=None, max_length=4096)
    github_token: SecretStr | None = Field(default=None, max_length=512)


class SourceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    target_binding: str = Field(min_length=1, max_length=2048)
    connector: Literal["json_snapshot", "aws_cloudwatch", "aws_alb", "github"] = "json_snapshot"
    config: SourceConfig = Field(default_factory=SourceConfig)
    credentials: SourceCredentials | None = None

    @field_validator("target_binding")
    @classmethod
    def target_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("target must be an HTTP origin or API base path without credentials")
        return value.rstrip("/")

    @model_validator(mode="after")
    def connector_fields(self) -> SourceInput:
        c, secret = self.config, self.credentials
        if self.connector in {"aws_cloudwatch", "aws_alb"}:
            remote_code = c.repository or c.commit or c.ref or c.paths
            if self.connector == "aws_cloudwatch" and (
                not c.region or not c.log_group or c.load_balancer or remote_code
            ):
                raise ValueError("AWS requires region and log group only")
            if self.connector == "aws_alb" and (
                not c.region or not c.account_id or not c.load_balancer or c.log_group
                or remote_code
            ):
                raise ValueError("An ALB source requires region, account and load balancer only")
            # No keys means the deployment's credential chain signs the read.
            if secret and (
                secret.github_token
                or bool(secret.access_key_id) != bool(secret.secret_access_key)
                or (secret.session_token and not secret.access_key_id)
            ):
                raise ValueError("AWS keys need both an access key ID and a secret, or neither")
        elif self.connector == "github":
            if not c.repository or c.region or c.log_group or c.account_id or c.load_balancer:
                raise ValueError("GitHub requires a repository")
            if bool(c.commit) != bool(c.paths) or not (c.commit or c.ref):
                raise ValueError(
                    "GitHub requires a branch or tag, or an immutable commit with exact paths"
                )
            if secret and (
                secret.access_key_id or secret.secret_access_key or secret.session_token
            ):
                raise ValueError("invalid GitHub credentials")
        elif (
            secret
            or c.region
            or c.log_group
            or c.load_balancer
            or c.account_id
            or c.repository
            or c.commit
            or c.ref
            or c.paths
        ):
            raise ValueError("JSON snapshots require no credentials or remote configuration")
        return self


class SourceUnavailable(Exception):
    """Only fixed codes cross the provider boundary."""

    def __init__(self, code: str = "source_unavailable"):
        self.code = code
        super().__init__(code)
