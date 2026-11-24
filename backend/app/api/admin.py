"""Administrative role management APIs."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..core.firebase import FirebaseConfigurationError, get_firebase_app


router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


class RoleAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole


@router.post("/users/{uid}/role")
def assign_role(
    uid: str,
    payload: RoleAssignmentRequest,
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> dict:
    if payload is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Role is required.")
    if uid == user.uid and payload.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="An administrator cannot remove their own ADMIN role.",
        )

    try:
        app = get_firebase_app()
        if app is None:
            raise FirebaseConfigurationError("Firebase Admin is not initialized")
        from firebase_admin import auth

        auth.set_custom_user_claims(uid, {"role": payload.role.value}, app=app)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Role assignment service unavailable.",
        ) from exc

    return {
        "uid": uid,
        "role": payload.role.value,
        "assigned_by": user.uid,
    }
