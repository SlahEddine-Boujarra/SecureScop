"""Integrity-checked registry of allow-listed remediation recipes.

Recipes reference reviewed artifacts by stable identifiers. Scanner, NVD, LLM,
and free-text content can never introduce an executable command.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from securescope.compliance.quick_remediation_service import EXECUTION_LEVELS
from securescope.paths import PROJECT_ROOT, REMEDIATION_RECIPES_FILE

APP_DIR = PROJECT_ROOT
DEFAULT_REGISTRY_PATH = REMEDIATION_RECIPES_FILE
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class RemediationRecipeError(ValueError):
    """Raised when a remediation recipe is malformed or fails integrity checks."""


@dataclass(frozen=True)
class RemediationRecipe:
    """Reviewed remediation recipe metadata.

    Args:
        recipe_id: Stable internal recipe identifier.
        title: Human-readable action title.
        execution_level: Guided, prepared, or approved execution level.
        operating_system_patterns: Supported OS match patterns.
        product_patterns: Supported product/component match patterns.
        finding_patterns: Supported vulnerability/title match patterns.
        precheck_id: Allow-listed pre-check identifier.
        command_id: Wazuh Active Response command identifier.
        artifact_path: Reviewed script/playbook path relative to the project.
        artifact_sha256: Expected artifact SHA-256 digest.
        expected_change: Observable intended change.
        restart_requirement: Restart/service-interruption guidance.
        rollback_action: Reviewed rollback guidance.
        required_privilege: Minimum execution privilege.
        expected_duration: Expected change duration.
        validation_method: Required post-change validation.
        compatible_wazuh_states: Agent states allowed for execution.
        version: Immutable recipe version.

    Returns:
        Immutable, validated recipe metadata.

    Raises:
        RemediationRecipeError: If any required field or checksum is invalid.
    """

    recipe_id: str
    title: str
    execution_level: str
    operating_system_patterns: tuple[str, ...]
    product_patterns: tuple[str, ...]
    finding_patterns: tuple[str, ...]
    precheck_id: str
    command_id: str
    artifact_path: str
    artifact_sha256: str
    expected_change: str
    restart_requirement: str
    rollback_action: str
    required_privilege: str
    expected_duration: str
    validation_method: str
    compatible_wazuh_states: tuple[str, ...]
    version: str

    def __post_init__(self) -> None:
        """Validate identifiers and mandatory operational metadata.

        Returns:
            None.

        Raises:
            RemediationRecipeError: If metadata is incomplete or unsafe.
        """

        identifiers = {
            "recipe_id": self.recipe_id,
            "precheck_id": self.precheck_id,
            "command_id": self.command_id,
        }
        for name, value in identifiers.items():
            if not IDENTIFIER_PATTERN.fullmatch(value):
                raise RemediationRecipeError(f"Invalid {name}: {value}")
        if self.execution_level not in EXECUTION_LEVELS:
            raise RemediationRecipeError(f"Unsupported execution level: {self.execution_level}")
        if not SHA256_PATTERN.fullmatch(self.artifact_sha256):
            raise RemediationRecipeError(f"Invalid artifact checksum for {self.recipe_id}.")
        required_text = {
            "title": self.title,
            "artifact_path": self.artifact_path,
            "expected_change": self.expected_change,
            "restart_requirement": self.restart_requirement,
            "rollback_action": self.rollback_action,
            "required_privilege": self.required_privilege,
            "expected_duration": self.expected_duration,
            "validation_method": self.validation_method,
            "version": self.version,
        }
        missing = [name for name, value in required_text.items() if not value.strip()]
        if missing:
            raise RemediationRecipeError("Recipe is missing: " + ", ".join(missing))
        if not self.operating_system_patterns or not self.compatible_wazuh_states:
            raise RemediationRecipeError("Recipe requires OS patterns and compatible Wazuh states.")

    def artifact(self, project_root: Path = APP_DIR) -> Path:
        """Resolve the reviewed artifact without allowing path traversal.

        Args:
            project_root: SecureScope project root.

        Returns:
            Absolute artifact path within ``project_root``.

        Raises:
            RemediationRecipeError: If the path escapes or is missing.
        """

        root = project_root.resolve()
        candidate = (root / self.artifact_path).resolve()
        if candidate != root and root not in candidate.parents:
            raise RemediationRecipeError(f"Recipe artifact escapes the project: {self.recipe_id}")
        if not candidate.is_file():
            raise RemediationRecipeError(f"Recipe artifact is missing: {self.artifact_path}")
        return candidate

    def verify_integrity(self, project_root: Path = APP_DIR) -> None:
        """Verify the artifact SHA-256 checksum.

        Args:
            project_root: SecureScope project root.

        Returns:
            None when the artifact matches the reviewed checksum.

        Raises:
            RemediationRecipeError: If the artifact checksum differs.
        """

        digest = hashlib.sha256(self.artifact(project_root).read_bytes()).hexdigest()
        if digest != self.artifact_sha256:
            raise RemediationRecipeError(
                f"Recipe artifact integrity check failed: {self.recipe_id}"
            )


def _text_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    """Normalize one required JSON string list.

    Args:
        value: Raw JSON array.
        field_name: Field name for validation errors.

    Returns:
        Non-empty trimmed tuple.

    Raises:
        RemediationRecipeError: If the value is not a non-empty string list.
    """

    if not isinstance(value, list):
        raise RemediationRecipeError(f"{field_name} must be a JSON list.")
    items = tuple(str(item).strip().casefold() for item in value if str(item).strip())
    if not items:
        raise RemediationRecipeError(f"{field_name} cannot be empty.")
    return items


def recipe_from_mapping(value: Mapping[str, Any]) -> RemediationRecipe:
    """Construct a validated recipe from JSON-compatible metadata.

    Args:
        value: Recipe metadata mapping.

    Returns:
        Validated recipe.

    Raises:
        RemediationRecipeError: If a field is absent or invalid.
    """

    if not isinstance(value, Mapping):
        raise RemediationRecipeError("Recipe metadata must be a mapping.")
    try:
        return RemediationRecipe(
            recipe_id=str(value["recipe_id"]).strip(),
            title=str(value["title"]).strip(),
            execution_level=str(value["execution_level"]).strip(),
            operating_system_patterns=_text_tuple(
                value["operating_system_patterns"], "operating_system_patterns"
            ),
            product_patterns=_text_tuple(value["product_patterns"], "product_patterns"),
            finding_patterns=_text_tuple(value["finding_patterns"], "finding_patterns"),
            precheck_id=str(value["precheck_id"]).strip(),
            command_id=str(value["command_id"]).strip(),
            artifact_path=str(value["artifact_path"]).strip(),
            artifact_sha256=str(value["artifact_sha256"]).strip().casefold(),
            expected_change=str(value["expected_change"]).strip(),
            restart_requirement=str(value["restart_requirement"]).strip(),
            rollback_action=str(value["rollback_action"]).strip(),
            required_privilege=str(value["required_privilege"]).strip(),
            expected_duration=str(value["expected_duration"]).strip(),
            validation_method=str(value["validation_method"]).strip(),
            compatible_wazuh_states=_text_tuple(
                value["compatible_wazuh_states"], "compatible_wazuh_states"
            ),
            version=str(value["version"]).strip(),
        )
    except KeyError as exc:
        raise RemediationRecipeError(f"Recipe field is missing: {exc.args[0]}") from exc


class RemediationRecipeRegistry:
    """Loaded collection of integrity-checked remediation recipes.

    Args:
        recipes: Validated recipes.
        project_root: Root used for artifact integrity checks.

    Returns:
        Registry supporting ID lookup and deterministic matching.

    Raises:
        RemediationRecipeError: If IDs are duplicated or integrity fails.
    """

    def __init__(
        self,
        recipes: Iterable[RemediationRecipe],
        project_root: Path = APP_DIR,
    ) -> None:
        """Validate all recipes and build immutable ID lookup.

        Args:
            recipes: Recipe iterable.
            project_root: Root used for artifact verification.

        Raises:
            RemediationRecipeError: If a recipe is duplicated or tampered with.
        """

        self.project_root = project_root.resolve()
        self._recipes: dict[str, RemediationRecipe] = {}
        for recipe in recipes:
            if recipe.recipe_id in self._recipes:
                raise RemediationRecipeError(f"Duplicate remediation recipe: {recipe.recipe_id}")
            recipe.verify_integrity(self.project_root)
            self._recipes[recipe.recipe_id] = recipe

    @classmethod
    def load(
        cls,
        path: Path = DEFAULT_REGISTRY_PATH,
        project_root: Path = APP_DIR,
    ) -> "RemediationRecipeRegistry":
        """Load an integrity-checked JSON registry.

        Args:
            path: JSON registry path.
            project_root: Root used for artifact verification.

        Returns:
            Loaded registry.

        Raises:
            RemediationRecipeError: If JSON, schema, or integrity is invalid.
        """

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RemediationRecipeError(str(exc)) from exc
        rows = payload.get("recipes") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            raise RemediationRecipeError("Recipe registry requires a recipes list.")
        return cls(
            (recipe_from_mapping(row) for row in rows),
            project_root=project_root,
        )

    def all(self) -> tuple[RemediationRecipe, ...]:
        """Return recipes in stable ID order.

        Returns:
            Immutable recipe tuple.

        Raises:
            ValueError: Never raised.
        """

        return tuple(self._recipes[key] for key in sorted(self._recipes))

    def get(self, recipe_id: str) -> RemediationRecipe:
        """Resolve exactly one allow-listed recipe.

        Args:
            recipe_id: Exact internal recipe ID.

        Returns:
            Integrity-checked recipe.

        Raises:
            RemediationRecipeError: If the recipe does not exist.
        """

        try:
            return self._recipes[str(recipe_id).strip()]
        except KeyError as exc:
            raise RemediationRecipeError(
                f"Remediation recipe is not allow-listed: {recipe_id}"
            ) from exc

    def match(self, finding: Mapping[str, Any]) -> RemediationRecipe | None:
        """Match a finding without evaluating or executing scanner text.

        Args:
            finding: Canonical finding and evidence metadata.

        Returns:
            First stable matching recipe, or ``None``.

        Raises:
            RemediationRecipeError: If finding input is not a mapping.
        """

        if not isinstance(finding, Mapping):
            raise RemediationRecipeError("Finding must be a mapping.")
        evidence = finding.get("most_recent_evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        os_text = " ".join(
            str(value or "")
            for value in (
                finding.get("operating_system"),
                finding.get("asset_operating_system"),
                evidence.get("operating_system"),
                evidence.get("os"),
            )
        ).casefold()
        product_text = " ".join(
            str(value or "")
            for value in (
                finding.get("component"),
                evidence.get("product"),
                evidence.get("service"),
            )
        ).casefold()
        finding_text = " ".join(
            str(value or "")
            for value in (
                finding.get("vulnerability_identity"),
                finding.get("title"),
                evidence.get("cve"),
                evidence.get("template_id"),
            )
        ).casefold()
        for recipe in self.all():
            os_match = any(pattern in os_text for pattern in recipe.operating_system_patterns)
            product_match = any(pattern in product_text for pattern in recipe.product_patterns)
            finding_match = any(pattern in finding_text for pattern in recipe.finding_patterns)
            if os_match and (product_match or finding_match):
                return recipe
        return None
