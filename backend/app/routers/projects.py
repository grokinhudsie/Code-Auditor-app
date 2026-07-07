from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.deps import check_origin, require_auth, require_user
from shared.db import SessionLocal
from shared.models import Project, User

router = APIRouter(prefix="/projects", dependencies=[Depends(require_auth)])


class ProjectUpsert(BaseModel):
    target: str
    name: str


@router.get("")
def list_projects(user: User = Depends(require_user)) -> dict:
    with SessionLocal() as session:
        projects = session.query(Project).filter(Project.user_id == user.id).all()
        return {"projects": [p.to_dict() for p in projects]}


@router.put("")
def upsert_project(
    req: ProjectUpsert, request: Request, user: User = Depends(require_user)
) -> dict:
    check_origin(request)
    name = req.name.strip()
    target = req.target.strip()
    if not name or len(name) > 100:
        raise HTTPException(422, "name must be 1-100 characters")
    if not target or len(target) > 2000:
        raise HTTPException(422, "invalid target")
    with SessionLocal() as session:
        project = (
            session.query(Project)
            .filter(Project.user_id == user.id, Project.target == target)
            .one_or_none()
        )
        if project is None:
            project = Project(user_id=user.id, target=target, name=name)
            session.add(project)
        else:
            project.name = name
        session.commit()
        return project.to_dict()


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str, request: Request, user: User = Depends(require_user)
) -> None:
    check_origin(request)
    with SessionLocal() as session:
        project = session.get(Project, project_id)
        if project is None or project.user_id != user.id:
            raise HTTPException(404, "project not found")
        session.delete(project)
        session.commit()
