"""
cyberresilient/services/evidence_service.py

Evidence Artifact Service — file upload, storage, retrieval, and linkage
to risks and controls.

Storage layout:
  evidence/
    risks/<risk_id>/<uuid><ext>
    controls/<control_id>/<uuid><ext>

Each artifact is recorded in the DB (with JSON sidecar fallback).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import uuid
from datetime import date
from pathlib import Path

from cyberresilient.config import DATA_DIR

EVIDENCE_DIR: Path = DATA_DIR.parent / "evidence"
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.\-]+$")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".docx",
    ".xlsx",
    ".csv",
    ".txt",
    ".eml",
    ".msg",
    ".zip",
}
MAX_FILE_SIZE_MB = 25


def _db_available() -> bool:
    try:
        from sqlalchemy import inspect

        from cyberresilient.database import get_engine

        return inspect(get_engine()).has_table("evidence_artifacts")
    except Exception:
        return False


def _artifact_dir(entity_type: str, entity_id: str) -> Path:
    if entity_type not in ("risk", "control"):
        raise ValueError(f"Invalid entity_type: {entity_type}")
    if not _SAFE_ID.match(entity_id):
        raise ValueError(f"Invalid entity_id: {entity_id}")
    d = EVIDENCE_DIR / entity_type / entity_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def upload_artifact(
    entity_type: str,
    entity_id: str,
    filename: str,
    file_bytes: bytes,
    description: str = "",
    uploaded_by: str = "system",
) -> dict:
    """
    Store an evidence artifact and record metadata.
    entity_type: 'risk' | 'control'
    Raises ValueError for bad type/size.
    """
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{suffix}' not allowed. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    size_mb = len(file_bytes) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(f"File {size_mb:.1f} MB exceeds limit of {MAX_FILE_SIZE_MB} MB.")

    artifact_id = str(uuid.uuid4())
    safe_name = f"{artifact_id}{suffix}"
    dest = _artifact_dir(entity_type, entity_id) / safe_name
    dest.write_bytes(file_bytes)

    meta = {
        "id": artifact_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "original_filename": filename,
        "stored_filename": safe_name,
        "description": description,
        "size_bytes": len(file_bytes),
        "sha256": _sha256(file_bytes),
        "uploaded_by": uploaded_by,
        "uploaded_at": date.today().isoformat(),
    }

    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import EvidenceArtifactRow
        from cyberresilient.services.audit_service import log_action

        session = get_session()
        try:
            session.add(EvidenceArtifactRow(**meta))
            log_action(
                session,
                action="upload_artifact",
                entity_type=entity_type,
                entity_id=entity_id,
                user=uploaded_by,
                after=meta,
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    else:
        dest.with_suffix(".json").write_text(json.dumps(meta, indent=2))

    return meta


def list_artifacts(entity_type: str, entity_id: str) -> list[dict]:
    """Return all artifacts for an entity, newest first."""
    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import EvidenceArtifactRow

        session = get_session()
        try:
            rows = (
                session.query(EvidenceArtifactRow)
                .filter_by(entity_type=entity_type, entity_id=entity_id)
                .order_by(EvidenceArtifactRow.uploaded_at.desc())
                .all()
            )
            return [r.to_dict() for r in rows]
        finally:
            session.close()
    d = _artifact_dir(entity_type, entity_id)
    results = []
    for m in sorted(d.glob("*.json"), reverse=True):
        with contextlib.suppress(Exception):
            results.append(json.loads(m.read_text()))
    return results


def get_artifact_bytes(entity_type: str, entity_id: str, artifact_id: str) -> tuple[bytes, str]:
    """Return (bytes, original_filename) for download."""
    meta = next(
        (a for a in list_artifacts(entity_type, entity_id) if a["id"] == artifact_id),
        None,
    )
    if not meta:
        raise FileNotFoundError(f"Artifact {artifact_id} not found.")
    stored = _artifact_dir(entity_type, entity_id) / meta["stored_filename"]
    return stored.read_bytes(), meta["original_filename"]


def delete_artifact(entity_type: str, entity_id: str, artifact_id: str, deleted_by: str = "system") -> None:
    meta = next(
        (a for a in list_artifacts(entity_type, entity_id) if a["id"] == artifact_id),
        None,
    )
    if not meta:
        raise FileNotFoundError(f"Artifact {artifact_id} not found.")
    d = _artifact_dir(entity_type, entity_id)
    for f in [d / meta["stored_filename"], (d / meta["stored_filename"]).with_suffix(".json")]:
        if f.exists():
            f.unlink()
    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import EvidenceArtifactRow
        from cyberresilient.services.audit_service import log_action

        session = get_session()
        try:
            row = session.query(EvidenceArtifactRow).filter_by(id=artifact_id).first()
            if row:
                session.delete(row)
                log_action(
                    session,
                    action="delete_artifact",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    user=deleted_by,
                    before=meta,
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def artifact_count(entity_type: str, entity_id: str) -> int:
    return len(list_artifacts(entity_type, entity_id))


def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024**2:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024**2):.1f} MB"


# ─────────────────────────────────────────────────────────────────────────────
# Multi-tenancy / framework evidence API
# Evidence layout:  evidence/{org_key}/{framework}/{control_slug}_{ts}_{filename}
# Metadata sidecar: same path + ".meta.json"
# ─────────────────────────────────────────────────────────────────────────────

STALE_DAYS = 365  # days before evidence is considered stale


def _org_fw_dir(org_key: str, framework: str) -> Path:
    """Return (and create) the per-org, per-framework evidence directory."""
    directory = EVIDENCE_DIR / _slug_fw(org_key) / _slug_fw(framework)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _slug_fw(value: str) -> str:
    """Filesystem-safe slug for org keys and framework names."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", value).strip("_")[:64]


def save_evidence(
    org_key: str,
    control_id: str,
    framework: str,
    file_bytes: bytes,
    filename: str,
    uploader: str = "system",
) -> dict:
    """Save an evidence file scoped to an org + framework + control.

    Returns the metadata dict on success.
    Raises ValueError for oversized or disallowed file types.
    """
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File type '{suffix}' not allowed. "
            f"Accepted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    size_mb = len(file_bytes) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(f"File {size_mb:.1f} MB exceeds the {MAX_FILE_SIZE_MB} MB limit.")

    ts = date.today().strftime("%Y%m%d")
    safe_control = _slug_fw(control_id)
    safe_stem = _slug_fw(Path(filename).stem)
    stored_name = f"{safe_control}_{ts}_{safe_stem}{suffix}"
    evidence_id = f"{_slug_fw(org_key)}__{safe_control}__{ts}__{safe_stem}"

    directory = _org_fw_dir(org_key, framework)
    file_path = directory / stored_name

    file_path.write_bytes(file_bytes)

    meta = {
        "evidence_id": evidence_id,
        "org_key": org_key,
        "framework": framework,
        "control_id": control_id,
        "original_filename": filename,
        "stored_filename": stored_name,
        "uploader": uploader,
        "collected_date": date.today().isoformat(),
        "file_size_bytes": len(file_bytes),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }

    sidecar = file_path.with_name(stored_name + ".meta.json")
    sidecar.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def list_evidence(
    org_key: str,
    control_id: str | None = None,
    framework: str | None = None,
) -> list[dict]:
    """Return evidence metadata dicts for an org, optionally filtered.

    Each dict includes extra fields:
    - ``stale``: bool
    - ``days_old``: int
    - ``download_path``: absolute path string for the data file
    """
    org_root = EVIDENCE_DIR / _slug_fw(org_key)
    if not org_root.exists():
        return []

    if framework:
        fw_dirs = [org_root / _slug_fw(framework)]
    else:
        fw_dirs = [d for d in org_root.iterdir() if d.is_dir()]

    today = date.today()
    results: list[dict] = []

    for fw_dir in fw_dirs:
        for sidecar in fw_dir.glob("*.meta.json"):
            try:
                meta = json.loads(sidecar.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            if control_id and meta.get("control_id") != control_id:
                continue

            collected_str = meta.get("collected_date", "")
            try:
                collected = date.fromisoformat(collected_str)
                days_old = (today - collected).days
            except (ValueError, TypeError):
                days_old = STALE_DAYS + 1

            meta["days_old"] = days_old
            meta["stale"] = days_old > STALE_DAYS
            meta["download_path"] = str(fw_dir / meta.get("stored_filename", ""))
            results.append(meta)

    results.sort(key=lambda m: m.get("collected_date", ""), reverse=True)
    return results


def delete_evidence(org_key: str, evidence_id: str) -> bool:
    """Delete evidence file + sidecar by evidence_id. Returns True if deleted."""
    org_root = EVIDENCE_DIR / _slug_fw(org_key)
    if not org_root.exists():
        return False

    for sidecar in org_root.rglob("*.meta.json"):
        try:
            meta = json.loads(sidecar.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        if meta.get("evidence_id") == evidence_id:
            data_file = sidecar.with_name(meta.get("stored_filename", ""))
            if data_file.exists():
                data_file.unlink()
            sidecar.unlink()
            return True

    return False


def get_evidence_summary(org_key: str) -> dict:
    """High-level stats for the evidence library header."""
    all_items = list_evidence(org_key)
    total = len(all_items)
    stale = sum(1 for m in all_items if m["stale"])
    frameworks: set[str] = {m.get("framework", "") for m in all_items}
    return {
        "total": total,
        "stale": stale,
        "fresh": total - stale,
        "frameworks": sorted(frameworks - {""}),
    }

