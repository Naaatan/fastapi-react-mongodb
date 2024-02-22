from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError

from routers import route_auth, route_todo
from schemas import CsrfSettings, SuccessMsg

app = FastAPI()
app.include_router(route_todo.router)
app.include_router(route_auth.router)

# CORS ホワイトリスト Origins
origins = ["http://localhost:3000"]

# ミドルウェア設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.get("/", response_model=SuccessMsg)
def root():
    return {"message": "Welcome to Fast API"}
