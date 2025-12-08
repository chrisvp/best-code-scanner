"""Authentication and user management endpoints."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import hash_password, verify_password, generate_session_token
from app.models.auth_models import User, UserSession, UserRole, UserStatus, FindingComment
from app.models.models import Finding
from app.api.deps import get_db, get_current_user, get_current_user_optional, require_admin, require_developer_or_admin

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ============================================================================
# Login / Logout
# ============================================================================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None, message: str = None):
    """Render login page."""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "message": message
    })


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Process login form."""
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password"
        }, status_code=401)

    if user.status == UserStatus.PENDING.value:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Your account is pending approval"
        }, status_code=403)

    if user.status == UserStatus.DISABLED.value:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Your account has been disabled"
        }, status_code=403)

    # Create session
    if remember:
        expires = datetime.now(timezone.utc) + timedelta(days=settings.SESSION_REMEMBER_DAYS)
    else:
        expires = datetime.now(timezone.utc) + timedelta(hours=settings.SESSION_TIMEOUT_HOURS)

    session = UserSession(
        user_id=user.id,
        token=generate_session_token(),
        expires_at=expires,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:500]
    )
    db.add(session)

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    # Set cookie and redirect
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=int((expires - datetime.now(timezone.utc)).total_seconds())
    )
    return response


@router.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """End user session."""
    token = request.cookies.get("session_token")
    if token:
        db.query(UserSession).filter(UserSession.token == token).delete()
        db.commit()

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_token")
    return response


# ============================================================================
# Signup
# ============================================================================

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request, error: str = None):
    """Render signup page."""
    return templates.TemplateResponse("signup.html", {
        "request": request,
        "error": error
    })


@router.post("/signup")
async def signup(
    request: Request,
    email: str = Form(...),
    display_name: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process signup form."""
    # Validation
    if password != confirm_password:
        return templates.TemplateResponse("signup.html", {
            "request": request,
            "error": "Passwords do not match",
            "email": email,
            "display_name": display_name
        }, status_code=400)

    if len(password) < settings.MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse("signup.html", {
            "request": request,
            "error": f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters",
            "email": email,
            "display_name": display_name
        }, status_code=400)

    # Check if email exists
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return templates.TemplateResponse("signup.html", {
            "request": request,
            "error": "Email already registered",
            "display_name": display_name
        }, status_code=400)

    # Check if this is the first user (becomes admin)
    user_count = db.query(User).count()
    is_first_user = user_count == 0

    user = User(
        email=email,
        display_name=display_name,
        hashed_password=hash_password(password),
        role=UserRole.ADMIN.value if is_first_user else UserRole.READONLY.value,
        status=UserStatus.ACTIVE.value if is_first_user else UserStatus.PENDING.value,
        approved_at=datetime.now(timezone.utc) if is_first_user else None
    )
    db.add(user)
    db.commit()

    if is_first_user:
        # Auto-login the first user
        session = UserSession(
            user_id=user.id,
            token=generate_session_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.SESSION_TIMEOUT_HOURS),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500]
        )
        db.add(session)
        user.last_login = datetime.now(timezone.utc)
        db.commit()

        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_token",
            value=session.token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=settings.SESSION_TIMEOUT_HOURS * 3600
        )
        return response

    return templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Account created! Please wait for admin approval."
    })


# ============================================================================
# User Management (Admin Only)
# ============================================================================

@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin)
):
    """User management page."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    pending_count = sum(1 for u in users if u.status == UserStatus.PENDING.value)

    return templates.TemplateResponse("users.html", {
        "request": request,
        "current_user": user,
        "users": users,
        "pending_count": pending_count,
        "roles": [r.value for r in UserRole],
        "statuses": [s.value for s in UserStatus]
    })


@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Approve a pending user."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.status = UserStatus.ACTIVE.value
    target.approved_at = datetime.now(timezone.utc)
    target.approved_by_id = admin.id
    db.commit()

    return JSONResponse({"success": True, "message": f"Approved {target.email}"})


@router.post("/users/{user_id}/reject")
async def reject_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Reject and delete a pending user."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.status != UserStatus.PENDING.value:
        raise HTTPException(status_code=400, detail="Can only reject pending users")

    db.delete(target)
    db.commit()

    return JSONResponse({"success": True, "message": f"Rejected {target.email}"})


@router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role: str = Form(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Update a user's role."""
    if role not in [r.value for r in UserRole]:
        raise HTTPException(status_code=400, detail="Invalid role")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == admin.id and role != UserRole.ADMIN.value:
        raise HTTPException(status_code=400, detail="Cannot demote yourself")

    target.role = role
    db.commit()

    return JSONResponse({"success": True, "message": f"Updated {target.email} to {role}"})


@router.post("/users/{user_id}/toggle-status")
async def toggle_user_status(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Enable/disable a user account."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot disable yourself")

    if target.status == UserStatus.DISABLED.value:
        target.status = UserStatus.ACTIVE.value
        msg = "enabled"
    else:
        target.status = UserStatus.DISABLED.value
        # Invalidate all sessions
        db.query(UserSession).filter(UserSession.user_id == target.id).delete()
        msg = "disabled"

    db.commit()
    return JSONResponse({"success": True, "message": f"Account {msg}"})


# ============================================================================
# Profile
# ============================================================================

@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """User profile page."""
    sessions = db.query(UserSession).filter(
        UserSession.user_id == user.id
    ).order_by(UserSession.created_at.desc()).all()

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "current_user": user,
        "sessions": sessions
    })


@router.post("/profile/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Change user password."""
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")

    if len(new_password) < settings.MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters")

    user.hashed_password = hash_password(new_password)
    db.commit()

    return JSONResponse({"success": True, "message": "Password changed"})


# ============================================================================
# Finding Status & Comments (Developer+)
# ============================================================================

@router.post("/finding/{finding_id}/status")
async def update_finding_status(
    finding_id: int,
    status: str = Form(...),
    comment: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_developer_or_admin)
):
    """Update finding status (FP, FIXED, IGNORED, VERIFIED)."""
    valid_statuses = ["VERIFIED", "FP", "FIXED", "IGNORED"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.status
    finding.status = status
    finding.status_changed_by_id = user.id
    finding.status_changed_at = datetime.now(timezone.utc)

    # Add comment if provided
    if comment.strip():
        action = f"changed_status_{old_status}_to_{status}"
        fc = FindingComment(
            finding_id=finding_id,
            user_id=user.id,
            comment=comment.strip(),
            action=action
        )
        db.add(fc)

    db.commit()

    return JSONResponse({
        "success": True,
        "message": f"Status changed to {status}",
        "status": status
    })


@router.post("/finding/{finding_id}/comment")
async def add_finding_comment(
    finding_id: int,
    comment: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Add a comment to a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not comment.strip():
        raise HTTPException(status_code=400, detail="Comment cannot be empty")

    fc = FindingComment(
        finding_id=finding_id,
        user_id=user.id,
        comment=comment.strip(),
        action=None
    )
    db.add(fc)
    db.commit()

    return JSONResponse({
        "success": True,
        "message": "Comment added",
        "comment_id": fc.id
    })


@router.get("/finding/{finding_id}/comments")
async def get_finding_comments(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Get all comments for a finding."""
    comments = db.query(FindingComment).filter(
        FindingComment.finding_id == finding_id
    ).order_by(FindingComment.created_at.desc()).all()

    return JSONResponse({
        "comments": [{
            "id": c.id,
            "user": c.user.display_name,
            "comment": c.comment,
            "action": c.action,
            "created_at": c.created_at.isoformat() if c.created_at else None
        } for c in comments]
    })
