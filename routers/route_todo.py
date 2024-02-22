from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi_csrf_protect import CsrfProtect
from starlette.status import HTTP_201_CREATED

from auth_utils import AuthJwtCsrf
from database import (
    db_create_todo,
    db_delete_todo,
    db_get_single_todo,
    db_get_todos,
    db_update_todo,
)
from schemas import SuccessMsg, Todo, TodoBody

router = APIRouter()
auth = AuthJwtCsrf()

@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    """Create a task.

    Args:
        request (Request): The request.
        response (Response): The response.
        data (TodoBody): The data to create a task.
        csrf_protect (CsrfProtect): csrf

    Raises:
        HTTPException: If the task creation failed.

    Returns:
        Todo: The created task.
    """
    # JWT と CSRF の検証と JWT token の更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)
    
    # json データから dict へ変換
    todo = jsonable_encoder(data)
    res = await db_create_todo(todo)
    
    # JWT token　の更新情報を cookie に登録
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {new_token}",
        httponly=AuthJwtCsrf.httponly,
        samesite=AuthJwtCsrf.samesite,
        secure=AuthJwtCsrf.secure,
    )
    
    # success
    if isinstance(res, dict):
        response.status_code = HTTP_201_CREATED
        return res

    # failed
    raise HTTPException(
        status_code=404, detail="Create task failed."
    )


@router.get("/api/todo", response_model=List[Todo])
async def get_todos(request: Request):
    """Get all tasks.
    
    Args:
        request (fastapi Request): The Request

    Returns:
        List[Todo]: All tasks.
    """
    # JWT token の検証
    auth.verify_jwt(request)

    res = await db_get_todos()
    return res


@router.get("/api/todo/{id}", response_model=Todo)
async def get_single_todo(request: Request, response: Response, id: str):
    """Get a task by ID.

    Args:
        request (fastapi request): The Request
        response (fastapi request): The Response
        id (str): The ID of the task to get.

    Raises:
        HTTPException: If the task doesn't exist.

    Returns:
        Todo: The task.
    """
    # JWT token の検証と更新
    new_token, _ = auth.verify_update_jwt(request)

    # DB からタスクを取得
    res = await db_get_single_todo(id)

    # JWT token の更新情報を cookie へ登録
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {new_token}",
        httponly=AuthJwtCsrf.httponly,
        samesite=AuthJwtCsrf.samesite,
        secure=AuthJwtCsrf.secure,
    )

    if isinstance(res, dict):
        return res
    raise HTTPException(
        status_code=404, detail=f"Task of ID:{id} doesn't exist."
    )


@router.put("/api/todo/{id}", response_model=Todo)
async def update_todo(
    request: Request, response: Response, id: str, data: TodoBody, csrf_protect: CsrfProtect = Depends()
):
    """Update a task by ID.

    Args:
        request (fastapi request): The Request
        response (fastapi request): The Response
        id (str): The ID of the task to update.
        data (TodoBody): The data to update.
        csrf_protect (CsrfProtect): csrf

    Raises:
        HTTPException: If the task doesn't exist.

    Returns:
        Todo: The updated task.
    """
    # JWT と CSRF の検証と JWT token の更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)

    todo = jsonable_encoder(data)
    res = await db_update_todo(id, todo)

    # JWT token　の更新情報を cookie に登録
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {new_token}",
        httponly=AuthJwtCsrf.httponly,
        samesite=AuthJwtCsrf.samesite,
        secure=AuthJwtCsrf.secure,
    )

    if isinstance(res, dict):
        return res
    raise HTTPException(
        status_code=404, detail="Update task failed."
    )


@router.delete("/api/todo/{id}", response_model=SuccessMsg)
async def delete_todo(request: Request, response: Response, id: str, csrf_protect: CsrfProtect = Depends()):
    """Delete a task by ID.

    Args:
        request (fastapi request): The Request
        response (fastapi request): The Response
        id (str): The ID of the task to delete.
        csrf_protect (CsrfProtect): csrf

    Raises:
        HTTPException: If the task doesn't exist.

    Returns:
        SuccessMsg: Successfully deleted.
    """
    # JWT と CSRF の検証と JWT token の更新
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)

    res = await db_delete_todo(id)

    # JWT token　の更新情報を cookie に登録
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {new_token}",
        httponly=AuthJwtCsrf.httponly,
        samesite=AuthJwtCsrf.samesite,
        secure=AuthJwtCsrf.secure,
    )

    if res is True:
        msg = SuccessMsg(message="Successfully deleted.")
        return jsonable_encoder(msg)
    raise HTTPException(
        status_code=404, detail="Delete task failed."
    )
