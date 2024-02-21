from datetime import datetime, timedelta

import jwt
from decouple import config
from fastapi import HTTPException, Request
from fastapi_csrf_protect import CsrfProtect
from passlib.context import CryptContext
from starlette.datastructures import Headers

JWT_KEY = config('JWT_KEY')

class AuthJwtCsrf():

    httponly: bool = True
    jwt_token_cookie_key: str = "access_token"
    secure: bool = True
    samesite: str = "none"

    def __init__(self) -> None:
        # Password context
        self.pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

        # Secret key for JWT
        self.secret_key = JWT_KEY

    def generate_hashed_pw(self, password: str) -> str:
        return self.pwd_ctx.hash(password)

    def verify_password(self, plain_pw: str, hashed_pw: str) -> bool:
        return self.pwd_ctx.verify(plain_pw, hashed_pw)

    def encode_jwt(self, email: str) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": email,
            "iat": now,
            "exp": now + timedelta(days=0, minutes=5)
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def decode_jwt(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="JWT token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid JWT token")

    def verify_jwt(self, request: Request) -> str:
        """Verify JWT Token in Request cookie

        Args:
            request (Request): fastapi Request

        Raises:
            HTTPException: 404 | No JWT exits

        Returns:
            str: subject
        """
        token = request.cookies.get(self.jwt_token_cookie_key)
        
        if token is None:
            raise HTTPException(
                status_code=404, detail="No JWT exist: may not set yet or deleted."
            )
            
        _, _, value = token.partition(" ")
        subject = self.decode_jwt(value)
        return subject
    
    def verify_update_jwt(self, request: Request) -> tuple[str, str]:
        """Verify JWT Token with update in Request cookie

        Args:
            request (Request): fastapi Request

        Returns:
            tuple[str, str]: (new_token, subject)
        """
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject
    
    def verify_csrf_update_jwt(self, request: Request, csrf_protect: CsrfProtect, headers: Headers) -> str:
        """Verify JWT Token and CSRF Token with update JWT token in Request cookie

        Args:
            request (Request): fast api Request
            csrf_protect (CsrfProtect): csrf
            headers (Headers): header

        Returns:
            str: _description_
        """
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        new_token, _ = self.verify_update_jwt(request)
        return new_token
    