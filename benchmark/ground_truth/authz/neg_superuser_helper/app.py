class PermissionDenied(Exception):
    pass


def _require_superuser(user):
    if not user.is_superuser:
        raise PermissionDenied


@router.post("/assignments")
async def create_assignment(payload, current_user, session):
    _require_superuser(current_user)
    user = await session.get(User, payload.user_id)
    return user.render()


@router.delete("/assignments/{assignment_id}")
async def delete_assignment(assignment_id, current_user, session):
    _require_superuser(current_user)
    assignment = await session.get(AuthzRoleAssignment, assignment_id)
    return assignment.render()
