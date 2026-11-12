"""Structural checks on steps, from the Provenance Records specification.

These checks are applied when steps are added and signed, so new records are
created correctly. They are not applied by Record.verify(), so records which
were signed before these checks existed still verify. Use Record.validate() to
check a received record.
"""

import collections
import datetime
import re

STEP_TYPES = ("permission", "origin", "transfer", "receipt", "process")

# ISO 8601 in UTC with Z, optionally with fractional seconds
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

# For each step type, the properties which refer to other steps: whether the
# property holds one id or a list of ids, and the types of step it may refer to.
REFERENCES: dict[str, dict[str, tuple[type, set[str]]]] = {
    "origin": {"permissions": (list, {"permission"})},
    "transfer": {
        "of": (str, {"origin", "process", "receipt"}),
        "permissions": (list, {"permission"}),
    },
    "receipt": {"transfer": (str, {"transfer"})},
    "process": {
        "inputs": (list, {"origin", "receipt", "process"}),
        "permissions": (list, {"permission"}),
    },
}


def is_timestamp(value) -> bool:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.match(value):
        return False
    try:
        datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _label(step):
    return f"Step {step.get('id', '(new)')}"


def step_problems(step: dict, label: str | None = None) -> list[str]:
    """Problems with a single step, without looking at the rest of the record."""
    label = label or _label(step)
    problems = []
    step_type = step.get("type")
    if step_type not in STEP_TYPES:
        problems.append(
            f"{label}: type must be one of {', '.join(STEP_TYPES)}, not {step_type!r}"
        )
    if not is_timestamp(step.get("timestamp")):
        problems.append(
            f"{label}: timestamp {step.get('timestamp')!r} is not an ISO 8601 time in UTC ending in Z"
        )
    if step_type == "permission" and "expires" in step:
        if not is_timestamp(step["expires"]):
            problems.append(
                f"{label}: expires {step['expires']!r} is not an ISO 8601 time in UTC ending in Z"
            )
    for prop, (shape, _) in REFERENCES.get(str(step_type), {}).items():
        if prop not in step:
            continue
        value = step[prop]
        if shape is str and not isinstance(value, str):
            problems.append(f"{label}: {prop} must be a step id")
        if shape is list and not (
            isinstance(value, list) and all(isinstance(v, str) for v in value)
        ):
            problems.append(f"{label}: {prop} must be a list of step ids")
    return problems


def reference_problems(step: dict, steps_by_id: dict) -> list[str]:
    """Problems with the steps that this step refers to."""
    problems = []
    for prop, (shape, allowed) in REFERENCES.get(str(step.get("type")), {}).items():
        value = step.get(prop)
        if shape is str:
            ids = [value] if isinstance(value, str) else []
        else:
            ids = (
                [v for v in value if isinstance(v, str)]
                if isinstance(value, list)
                else []
            )
        for step_id in ids:
            target = steps_by_id.get(step_id)
            if target is None:
                problems.append(
                    f"{_label(step)}: {prop} refers to {step_id}, which is not in this record"
                )
            elif target.get("type") not in allowed:
                problems.append(
                    f"{_label(step)}: {prop} must refer to {' or '.join(sorted(allowed))} steps, "
                    f"but {step_id} is a {target.get('type')} step"
                )
    return problems


def duplicate_ids(steps) -> list[str]:
    counts = collections.Counter(s.get("id") for s in steps)
    return sorted(str(i) for i, n in counts.items() if n > 1)


def record_problems(steps: list[dict]) -> list[str]:
    """All structural problems in a record's steps."""
    problems = []
    duplicates = duplicate_ids(steps)
    if duplicates:
        problems.append("Step ids are used more than once: " + ", ".join(duplicates))
    if not any(s.get("type") == "origin" for s in steps):
        problems.append("A Provenance record must contain at least one origin step")
    steps_by_id = {s.get("id"): s for s in steps}
    for step in steps:
        problems.extend(step_problems(step))
        problems.extend(reference_problems(step, steps_by_id))
    return problems
