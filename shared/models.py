import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    # source_type "git" scans git_url; "local" copies local_path off the docker host
    source_type: Mapped[str] = mapped_column(String(16), default="git")
    git_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    local_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    # queued | cloning | copying | scanning | triaging | patching | completed | failed
    status: Mapped[str] = mapped_column(String(32), default="queued")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_tree: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def to_dict(self, include_findings: bool = True) -> dict:
        data = {
            "id": self.id,
            "source_type": self.source_type,
            "git_url": self.git_url,
            "local_path": self.local_path,
            "status": self.status,
            "error": self.error,
            "file_tree": self.file_tree,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


class Finding(Base):
    """Unified finding schema (BUILD_PLAN §5). `id` is the stable content hash
    (scanner + rule + file + line + snippet); PK is composite with scan_id so
    the same finding can recur across scans while staying cacheable."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    scanner: Mapped[str] = mapped_column(String(32))  # trivy | semgrep | gitleaks
    category: Mapped[str] = mapped_column(String(16))  # sca | sast | secret | iac
    rule_id: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    raw_severity: Mapped[str] = mapped_column(String(32))
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)

    # filled in by the LLM layer
    triaged_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    likely_false_positive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    suggested_patch: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "raw_severity": self.raw_severity,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "cve_ids": self.cve_ids or [],
            "references": self.references or [],
            "triaged_severity": self.triaged_severity,
            "likely_false_positive": self.likely_false_positive,
            "explanation": self.explanation,
            "suggested_patch": self.suggested_patch,
            "patch_rationale": self.patch_rationale,
        }
