"""Target-site tables.

These live in the same database as the detection platform so they share one
engine and session factory. They are prefixed `site_` to stay clearly separate
from the SOC tables.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from ..models import utcnow


class SiteUser(Base):
    """A student who owns a mini-site on the target app.

    The password is stored in plaintext ON PURPOSE — it makes the SQL-injection
    data-dump demo land ("look, your password leaked") and lets the brute-force
    runner actually succeed. Never do this outside a throwaway lab target.
    """

    __tablename__ = "site_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(120))  # plaintext, deliberately
    display_name: Mapped[str] = mapped_column(String(80))
    # The student's "private" data — what SQLi / traversal is meant to expose.
    secret_note: Mapped[str] = mapped_column(Text, default="")
    # Synthetic address this site is reachable at inside the SOC's view, so the
    # dashboard can attribute attacks to this specific student.
    asset_ip: Mapped[str] = mapped_column(String(45), index=True, default="")

    # Live state the attacks mutate, so the student's own page changes visibly.
    is_defaced: Mapped[bool] = mapped_column(Boolean, default=False)
    is_breached: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    guestbook: Mapped[list["GuestbookEntry"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )


class GuestbookEntry(Base):
    """A public message on a student's site. Rendered UNescaped by the frontend,
    which is the stored-XSS surface."""

    __tablename__ = "site_guestbook"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("site_users.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(80), default="guest")
    message: Mapped[str] = mapped_column(Text)  # stored raw, on purpose
    is_attack: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    site: Mapped[SiteUser] = relationship(back_populates="guestbook")
