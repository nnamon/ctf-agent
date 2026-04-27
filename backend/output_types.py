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
      * `flag_found` requires `flag` + `method`. Used only when the solver has
        actually executed the exploit and read the real flag value.
      * `gave_up` requires `reason`. Used when the solver has genuinely
        exhausted its ideas. Emitting this lets the swarm bump-and-retry with
        sibling insights instead of misreading a placeholder string as a win.

    Required-field-per-mode is enforced by the parsing code, not the schema —
    OpenAI's structured-output endpoints only accept a strict subset of JSON
    Schema where `oneOf` discriminated unions are flaky.
    """
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["flag_found", "gave_up"]},
            "flag": {"type": "string"},
            "method": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["type"],
        "additionalProperties": False,
    }
