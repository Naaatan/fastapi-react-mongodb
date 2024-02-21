from fastapi import APIRouter, Depends, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi_csrf_protect import CsrfProtect
from starlette.status import HTTP_201_CREATED

from auth_utils import AuthJwtCsrf
from database import db_login, db_signup
from schemas import Csrf, SuccessMsg, UserBody, UserInfo

router = APIRouter()
auth = AuthJwtCsrf()

@router.get("/api/csrftoken", response_model=Csrf)
def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.generate_csrf()
    csrf = Csrf(csrf_token=csrf_token)
    return jsonable_encoder(csrf)


@router.post("/api/signup", response_model=UserInfo)
async def signup(request:Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    # CSRF token をヘッダーから取得
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    # CSRF token を検証
    csrf_protect.validate_csrf(csrf_token)
    
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    response.status_code = HTTP_201_CREATED
    return new_user


@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    # CSRF token をヘッダーから取得
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    # CSRF token を検証
    csrf_protect.validate_csrf(csrf_token)

    user = jsonable_encoder(user)
    token = await db_login(user)

    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {token}",
        httponly=AuthJwtCsrf.httponly,
        secure=AuthJwtCsrf.secure,
        samesite=AuthJwtCsrf.samesite,
    )
    msg = SuccessMsg(message="Logged in successfully.")
    return jsonable_encoder(msg)


@router.post("/api/logout", response_model=SuccessMsg)
def logout(request, Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    # CSRF token をヘッダーから取得
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    # CSRF token を検証
    csrf_protect.validate_csrf(csrf_token)

    # cookie の JWT token を破棄する
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value="",
        httponly=AuthJwtCsrf.httponly,
        secure=AuthJwtCsrf.secure,
        samesite=AuthJwtCsrf.samesite,
    )
    
    msg = SuccessMsg(message="Successfully logged-out")
    return jsonable_encoder(msg)


@router.get("/api/user", response_model=UserInfo)
def get_user_refresh_jwt(request: Request, response: Response):
    # JWT token　の検証と更新
    new_token, subject = auth.verify_update_jwt(request)

    # JWT token の更新情報を登録
    response.set_cookie(
        key=AuthJwtCsrf.jwt_token_cookie_key,
        value=f"Bearer {new_token}",
        httponly=AuthJwtCsrf.httponly,
        secure=AuthJwtCsrf.secure,
        samesite=AuthJwtCsrf.samesite,
    )
    
    user_info = UserInfo(email=subject)
    return jsonable_encoder(user_info)
