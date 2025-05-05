import os
import logging
import json
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.api import api_router
from app.core.config import settings
from app.trpc.router import TRPCRouter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.PROJECT_NAME, version="0.1.0")

# CORS middleware
origins = settings.ALLOWED_ORIGINS
if origins == "*":
    origins = ["*"]  # FastAPI needs it as a list
elif isinstance(origins, str):
    origins = origins.split(",")  # Convert comma-separated string to list

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to mask sensitive data in logs
class SensitiveDataMaskingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Process the request
        response = await call_next(request)
        
        # If it's a JSON response, mask sensitive data
        if response.headers.get("content-type") == "application/json":
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            try:
                # Parse the JSON response
                data = json.loads(body.decode())
                
                # Mask sensitive fields
                if isinstance(data, dict) and "encrypted_private_key" in data:
                    data["encrypted_private_key"] = "***MASKED***"
                
                # Serialize back to JSON
                modified_body = json.dumps(data).encode()
                
                # Create a new response with masked data
                return Response(
                    content=modified_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
            except Exception as e:
                logger.error(f"Error masking sensitive data: {e}")
                # If there's an error, return the original response
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
        
        return response

app.add_middleware(SensitiveDataMaskingMiddleware)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Create tRPC router instance
trpc_router = TRPCRouter()

# tRPC endpoint for auth
@app.post("/trpc/auth.signup")
async def trpc_signup(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return await trpc_router.signup(token)

# tRPC endpoint for keys
@app.post("/trpc/keys.create")
async def trpc_create_key(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data = await request.json()
    return await trpc_router.create_key(data, token)

@app.get("/trpc/keys.get")
async def trpc_get_key(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return await trpc_router.get_key(token)

@app.put("/trpc/keys.update")
async def trpc_update_key(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data = await request.json()
    return await trpc_router.update_key(data, token)

# tRPC endpoint for recovery
@app.post("/trpc/recovery.createShares")
async def trpc_create_recovery_shares(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data = await request.json()
    return await trpc_router.create_recovery_shares(data, token)

@app.post("/trpc/recovery.verifyShares")
async def trpc_verify_recovery_shares(request: Request):
    data = await request.json()
    return await trpc_router.verify_recovery_shares(data)

@app.post("/trpc/recovery.recoverKey")
async def trpc_recover_key(request: Request):
    data = await request.json()
    return await trpc_router.recover_key(data)

@app.get("/ping")
async def ping():
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
