"""FastAPI application for the LLM Guardrail Proxy."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from config import settings
from audit_logger import audit_logger
from llm_client import get_llm_client


# Global instances for AI models (initialized in lifespan)
pii_detector = None
injection_detector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager.
    
    Note: Models are initialized lazily on first request to avoid mutex lock issues
    with --reload. This is safer than initializing here.
    """
    # Application runs here - models will be loaded on first use
    yield
    
    # Cleanup (optional, but good practice)
    print("Shutting down...")


app = FastAPI(
    title="LLM Guardrail Proxy",
    description="Security middleware for LLM applications",
    version="1.0.0",
    lifespan=lifespan
)


class PromptRequest(BaseModel):
    """Request model for chat endpoint."""
    user_query: str


class ChatResponse(BaseModel):
    """Response model for chat endpoint."""
    response: str


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address as string
    """
    # Check for forwarded IP (if behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # Check for real IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "LLM Guardrail Proxy"}


def _ensure_models_loaded():
    """Lazy load AI models on first request.
    
    This function ensures models are only initialized when actually needed.
    The lightweight detectors use regex and pattern matching (no heavy C++ dependencies),
    so they load quickly without mutex lock issues.
    """
    global pii_detector, injection_detector
    
    if pii_detector is None:
        print("Loading PII detector (lazy initialization)...")
        try:
            from pii_detector import PIIDetector
            pii_detector = PIIDetector()
            print("✓ PII detector loaded")
        except Exception as e:
            print(f"⚠ Warning: Error loading PII detector: {e}")
            raise
    
    if injection_detector is None:
        print("Loading injection detector (lazy initialization)...")
        try:
            from injection_detector import InjectionDetector
            injection_detector = InjectionDetector()
            print("✓ Injection detector loaded")
        except Exception as e:
            print(f"⚠ Warning: Error loading injection detector: {e}")
            raise


@app.post("/chat", response_model=ChatResponse)
async def secure_chat(request: PromptRequest, http_request: Request):
    """Secure chat endpoint with PII and injection detection.
    
    Args:
        request: The prompt request
        http_request: FastAPI request object for IP extraction
        
    Returns:
        ChatResponse with LLM-generated response
        
    Raises:
        HTTPException: If PII or injection is detected
    """
    # Lazy load models on first request (avoids mutex lock issues with --reload)
    _ensure_models_loaded()
    
    user_query = request.user_query
    client_ip = get_client_ip(http_request)
    
    # Step 1: Check for PII/Sensitive Data
    if pii_detector.contains_sensitive_data(user_query):
        # Log the security incident
        audit_logger.log_pii_detection(client_ip, user_query)
        
        # Get entity details for better error message
        entities = pii_detector.get_entity_summary(user_query)
        
        raise HTTPException(
            status_code=400,
            detail=f"Security Alert: PII or Secrets detected. {entities}"
        )
    
    # Step 2: Check for Prompt Injection
    llm_client = get_llm_client()
    is_injection, detection_method = await injection_detector.is_jailbreak_attempt(
        user_query,
        llm_client=llm_client
    )
    
    if is_injection:
        # Log the security incident
        audit_logger.log_injection_detection(client_ip, user_query)
        
        raise HTTPException(
            status_code=403,
            detail=f"Security Alert: Prompt Injection detected via {detection_method}."
        )
    
    # Step 3: If safe, call the actual LLM
    try:
        response_text = await llm_client.generate_response(user_query)
        
        # Step 4: Log the safe request
        audit_logger.log_safe_request(client_ip, user_query)
        
        return ChatResponse(response=response_text)
        
    except Exception as e:
        # Log the error but don't expose internal details
        audit_logger.log_security_event(
            ip_address=client_ip,
            attack_type="LLM_ERROR",
            payload=user_query,
            status="ERROR"
        )
        
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request."
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom exception handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

