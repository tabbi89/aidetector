"""Shared bases every API schema builds on."""

from __future__ import annotations

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
)

from app.scans.run_options import RESOURCE_ID_PATTERN, RESOURCE_NAME_PATTERN


class ResponseModel(BaseModel):
    """The API serializes defaults too; document their presence in output schemas."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


class HealthOut(ResponseModel):
    status: str
    # Whether the dev-only example endpoints answer, so the UI can offer them.
    examples: bool = False


class ErrorOut(ResponseModel):
    detail: str


#: A resource name in ``predefined_resource_ids`` — the spec-derived key a
#: dependent operation's path parameter is matched on (``merchant`` for
#: ``merchantId``). Identifier-shaped, so it cannot smuggle path syntax.
ResourceName = Annotated[str, StringConstraints(pattern=RESOURCE_NAME_PATTERN)]

#: The id itself: opaque and target-owned, so nearly anything goes — except the
#: characters that would let it break out of the path segment it is rendered
#: into (``/?#`` and CR/LF).
ResourceId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=RESOURCE_ID_PATTERN),
]
