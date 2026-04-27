"""Structured output types for solver agents."""

from typing import Literal, Union

from pydantic import BaseModel


class FlagFound(BaseModel):
    type: Literal["flag_found"] = "flag_found"
    flag: str
    method: str  # brief description of how


class GaveUp(BaseModel):
    type: Literal["gave_up"] = "gave_up"
    reason: str  # honest description of why no flag was found


# Pydantic AI discriminated union (resolved via the Literal `type` field).
SolverOutput = Union[FlagFound, GaveUp]


def solver_output_json_schema() -> dict:
    """JSON schema for solver structured output — shared by Claude SDK and Codex.

    Two modes:
      * `flag_found` populates `flag` + `method`, leaves `reason` null. Used
        only when the solver has actually executed the exploit and read the
        real flag value.
      * `gave_up` populates `reason`, leaves `flag` + `method` null. Used when
        the solver has genuinely exhausted its ideas; lets the swarm
        bump-and-retry instead of misreading a placeholder string as a win.

    OpenAI's strict structured-output endpoints require every property in
    `required` and reject `oneOf` discriminated unions, so the schema is a
    flat object with nullable string fields and the per-mode required
    populating is enforced by the parsing code.
    """
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["flag_found", "gave_up"]},
            "flag": {"type": ["string", "null"]},
            "method": {"type": ["string", "null"]},
            "reason": {"type": ["string", "null"]},
        },
        "required": ["type", "flag", "method", "reason"],
        "additionalProperties": False,
    }
