"""
API router for the Auth service
"""
from fastapi import APIRouter

from app.api.v1 import routes_auth, routes_keys, routes_recovery

api_router = APIRouter()

# Include all routers
api_router.include_router(routes_auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(routes_keys.router, prefix="/keys", tags=["keys"])
api_router.include_router(routes_recovery.router, prefix="/recovery", tags=["recovery"])
