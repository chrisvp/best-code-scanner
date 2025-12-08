"""User authentication and authorization models."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Index
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


def local_now():
    """Return current local datetime for database defaults."""
    return datetime.now().astimezone()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    READONLY = "readonly"


class UserStatus(str, enum.Enum):
    PENDING = "pending"      # Awaiting admin approval
    ACTIVE = "active"        # Approved and can login
    DISABLED = "disabled"    # Account disabled by admin


class User(Base):
    """User account for authentication and authorization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    display_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default=UserRole.READONLY.value)
    status = Column(String, default=UserStatus.PENDING.value)

    created_at = Column(DateTime(timezone=True), default=local_now)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    approved_by = relationship("User", remote_side=[id], foreign_keys=[approved_by_id])
    comments = relationship("FindingComment", back_populates="user")


class UserSession(Base):
    """Active login session for a user."""
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=local_now)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("idx_sessions_expires", "expires_at"),
    )


class FindingComment(Base):
    """Comments and status change history for findings."""
    __tablename__ = "finding_comments"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    comment = Column(Text, nullable=False)
    action = Column(String, nullable=True)  # "marked_fp", "reopened", "marked_fixed", etc.
    created_at = Column(DateTime(timezone=True), default=local_now)

    finding = relationship("Finding", back_populates="comments")
    user = relationship("User", back_populates="comments")

    __table_args__ = (
        Index("idx_comments_finding", "finding_id"),
    )
