"""Machine-readable Charter documents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .canonical import sha256_json
from .shadow_eval import CandidateEvalError, CandidateEvalPolicy


class CharterError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise CharterError("Charter object keys must be strings")
        if key in mapping:
            raise CharterError(f"duplicate Charter key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class CharterClause:
    id: str
    severity: str
    statement: str
    rule: str
    parameters: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CharterClause:
        if not isinstance(value, dict):
            raise CharterError("each Charter clause must be an object")
        required = {"id", "severity", "statement", "rule"}
        allowed = required | {"parameters"}
        missing = sorted(required - value.keys())
        extra = sorted(value.keys() - allowed)
        if missing or extra:
            raise CharterError(f"clause fields mismatch; missing={missing}, extra={extra}")
        for field in ("id", "severity", "statement", "rule"):
            if not isinstance(value[field], str) or not value[field]:
                raise CharterError(f"clause {field} must be a non-empty string")
        severity = value["severity"]
        if severity not in {"hard", "soft"}:
            raise CharterError(f"invalid severity for {value['id']}: {severity}")
        parameters = value.get("parameters", {})
        if not isinstance(parameters, dict):
            raise CharterError(f"parameters must be an object for {value['id']}")
        rule = value["rule"]
        parameter_contract = {
            "immutable_artifacts": {},
            "freeze_on_integrity_failure": {},
            "promotion_evidence_required": {
                "events": ["config.resolved", "batch.committed", "source_eval.result", "weights.published"]
            },
        }
        if rule == "candidate_shadow_evaluation":
            if severity != "hard":
                raise CharterError("candidate shadow-evaluation policy must be hard")
            try:
                CandidateEvalPolicy.from_parameters(parameters)
            except CandidateEvalError as exc:
                raise CharterError(f"unsupported parameters for {value['id']} ({rule}): {exc}") from exc
        elif rule not in parameter_contract:
            raise CharterError(f"unknown Charter rule: {rule}")
        elif parameters != parameter_contract[rule]:
            raise CharterError(f"unsupported parameters for {value['id']} ({rule})")
        return cls(
            id=value["id"],
            severity=severity,
            statement=value["statement"],
            rule=rule,
            parameters=parameters,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "statement": self.statement,
            "rule": self.rule,
            "parameters": self.parameters,
        }


@dataclass(frozen=True)
class Charter:
    version: int
    clauses: tuple[CharterClause, ...]

    @classmethod
    def load(cls, path: str | Path) -> Charter:
        try:
            raw = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        except (OSError, yaml.YAMLError) as exc:
            raise CharterError(f"cannot load Charter: {exc}") from exc
        if not isinstance(raw, dict):
            raise CharterError("Charter root must be an object")
        if set(raw) != {"version", "clauses"}:
            raise CharterError("Charter root fields must be exactly version and clauses")
        if isinstance(raw.get("version"), bool) or raw.get("version") != 1:
            raise CharterError("unsupported Charter version")
        raw_clauses = raw.get("clauses")
        if not isinstance(raw_clauses, list) or not raw_clauses:
            raise CharterError("Charter must contain at least one clause")
        clauses = tuple(CharterClause.from_dict(item) for item in raw_clauses)
        ids = [clause.id for clause in clauses]
        if len(ids) != len(set(ids)):
            raise CharterError("Charter clause IDs must be unique")
        if sum(clause.rule == "candidate_shadow_evaluation" for clause in clauses) > 1:
            raise CharterError("Charter may contain at most one candidate shadow-evaluation policy")
        return cls(version=1, clauses=clauses)

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "clauses": [clause.to_dict() for clause in self.clauses]}

    def clauses_for_rule(self, rule: str) -> tuple[CharterClause, ...]:
        return tuple(clause for clause in self.clauses if clause.rule == rule)

    def candidate_eval_policy(self) -> CandidateEvalPolicy | None:
        clauses = self.clauses_for_rule("candidate_shadow_evaluation")
        if not clauses:
            return None
        clause = clauses[0]
        if clause.severity != "hard":
            raise CharterError("candidate shadow-evaluation policy must be hard")
        return CandidateEvalPolicy.from_parameters(clause.parameters)
