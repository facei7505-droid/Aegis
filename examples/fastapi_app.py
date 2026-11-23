"""Protect a FastAPI / Starlette app.

    pip install aegis-selfheal fastapi uvicorn
    uvicorn examples.fastapi_app:app
"""
from fastapi import FastAPI

from aegis.integrations import protect_asgi

api = FastAPI()


@api.get("/items")
def items(q: str = ""):
    return {"q": q}


app = protect_asgi(api, mode="block", heal="propose", app_name="items-api")
