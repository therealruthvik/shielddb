from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import json

from duogaurd_mcp.server import moderator, db_conn, security_violations, record_violation, secure_query, secure_insert, secure_delete_or_drop, db_status

# Initialize FastAPI application
app = FastAPI(
    title="ShieldDB Security Gateway API",
    description="Backend API services supporting the ShieldDB Security Dashboard and interactive playground."
)

# Enable CORS for standard local development (Vite runs on port 5173 by default)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for easy hackathon setup
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global query stats for dashboard analytics
api_stats = {
    "queries_processed": 0,
    "blocked_queries": 0,
    "total_redactions": 0,
    "latencies": [],  # List of last 100 response latencies
}

# Mapping of risk categories to comprehensive descriptions and mitigation guide
CATEGORY_METADATA = {
    "Violent crimes": {
        "description": "Details, guides, or incitement of physical violence, terrorism, or bodily harm.",
        "threat_level": "CRITICAL",
        "action": "Immediate Block & System Alert. Halt downstream agent execution."
    },
    "Non-violent crimes": {
        "description": "Information on illegal acts not involving physical harm, such as hacking, theft, or piracy.",
        "threat_level": "HIGH",
        "action": "Block command. Log user ID for audit compliance."
    },
    "Sex-related crimes": {
        "description": "Content depicting sexual coercion, non-consensual acts, or sexual harassment.",
        "threat_level": "CRITICAL",
        "action": "Immediate Block & System Alert."
    },
    "Child sexual exploitation": {
        "description": "Any content relating to the exploitation, harm, or abuse of minors.",
        "threat_level": "CRITICAL",
        "action": "Immediate Hard Block. Terminate user session and log details."
    },
    "Specialized advice": {
        "description": "Steering users with legal advice, medical diagnoses, or definitive stock market/financial planning.",
        "threat_level": "MEDIUM",
        "action": "Flag result. Inject compliance disclaimer into agent response."
    },
    "Privacy": {
        "description": "Exposure of sensitive PII (Social Security Numbers, credit cards, passwords, phone numbers).",
        "threat_level": "HIGH",
        "action": "Activate Outbound Redactor. Scrub PII from JSON outputs."
    },
    "Intellectual property": {
        "description": "Requests to bypass copyright protections, software DRM, or reproduce copyrighted content.",
        "threat_level": "MEDIUM",
        "action": "Filter output. Block specific copy-generation queries."
    },
    "Indiscriminate weapons": {
        "description": "Creation or acquisition guidelines for chemical, biological, or nuclear weapons.",
        "threat_level": "CRITICAL",
        "action": "Immediate Hard Block. Halt agent execution."
    },
    "Hate": {
        "description": "Hate speech, slurs, or harassment targeting race, religion, gender, or orientation.",
        "threat_level": "HIGH",
        "action": "Block insert/query. Log content to security logs."
    },
    "Suicide and self-harm": {
        "description": "Content encouraging self-destruction, cutting, or suicide.",
        "threat_level": "CRITICAL",
        "action": "Immediate Block. Inject safety resource text and hotlines."
    },
    "Sexual content": {
        "description": "Erotica, pornographic text, or adult content.",
        "threat_level": "LOW",
        "action": "Block content representation in standard public databases."
    },
    "Jailbreak prompts": {
        "description": "Adversarial prompts designed to ignore rules, act as unrestricted agents, or leak system prompts.",
        "threat_level": "CRITICAL",
        "action": "Immediate Block. Flush agent context window to clear malicious instructions."
    }
}

# --- Request Models ---

class ModerationRequest(BaseModel):
    text: str = Field(..., description="Text to screen with DuoGuard")
    threshold: float = Field(0.5, description="Safety sensitivity threshold")

class QueryRequest(BaseModel):
    collection: str = Field(..., description="Collection name")
    query: Optional[str] = Field(None, description="JSON string representation of MongoDB query filter")
    projection: Optional[str] = Field(None, description="JSON string representation of fields projection")
    threshold: float = Field(0.5, description="Safety threshold")

class InsertRequest(BaseModel):
    collection: str = Field(..., description="Collection name")
    document: str = Field(..., description="JSON string representation of document to insert")
    threshold: float = Field(0.5, description="Safety threshold")

class DeleteRequest(BaseModel):
    collection: str = Field(..., description="Collection name")
    query: Optional[str] = Field(None, description="JSON string representation of query")
    drop_collection: bool = Field(False, description="Drop the entire collection")
    threshold: float = Field(0.5, description="Safety threshold")


# --- API Routes ---

@app.post("/api/moderate")
def api_moderate(payload: ModerationRequest):
    """Screens a single prompt/text block through the safety moderator engine."""
    start_time = time.time()
    try:
        result = moderator.evaluate_text(payload.text, payload.threshold)
        
        # Calculate latency in ms
        latency_ms = int((time.time() - start_time) * 1000)
        api_stats["latencies"].append(latency_ms)
        if len(api_stats["latencies"]) > 100:
            api_stats["latencies"].pop(0)
            
        result["latency_ms"] = latency_ms
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/query")
def api_query(payload: QueryRequest):
    """Exposes the secure_query tool over REST with performance logging."""
    start_time = time.time()
    api_stats["queries_processed"] += 1
    try:
        # Call the secure MCP tool directly
        result = secure_query(
            collection=payload.collection,
            query=payload.query,
            projection=payload.projection,
            threshold=payload.threshold
        )
        
        latency_ms = int((time.time() - start_time) * 1000)
        api_stats["latencies"].append(latency_ms)
        
        result["latency_ms"] = latency_ms
        
        if result.get("security_alert"):
            api_stats["blocked_queries"] += 1
        if result.get("redaction_applied"):
            api_stats["total_redactions"] += 1
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/insert")
def api_insert(payload: InsertRequest):
    """Exposes the secure_insert tool over REST."""
    start_time = time.time()
    api_stats["queries_processed"] += 1
    try:
        result = secure_insert(
            collection=payload.collection,
            document=payload.document,
            threshold=payload.threshold
        )
        
        latency_ms = int((time.time() - start_time) * 1000)
        api_stats["latencies"].append(latency_ms)
        result["latency_ms"] = latency_ms
        
        if result.get("security_alert"):
            api_stats["blocked_queries"] += 1
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/delete")
def api_delete(payload: DeleteRequest):
    """Exposes secure delete or drop tools over REST."""
    start_time = time.time()
    api_stats["queries_processed"] += 1
    try:
        result = secure_delete_or_drop(
            collection=payload.collection,
            query=payload.query,
            drop_collection=payload.drop_collection,
            threshold=payload.threshold
        )
        
        latency_ms = int((time.time() - start_time) * 1000)
        api_stats["latencies"].append(latency_ms)
        result["latency_ms"] = latency_ms
        
        if result.get("security_alert"):
            api_stats["blocked_queries"] += 1
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def get_categories_metadata():
    """Retrieves categories metadata from DB rules collection, falling back to static metadata if empty or failed."""
    try:
        rules_col = db_conn.get_collection("rules")
        if rules_col is not None:
            rules = list(rules_col.find({}, {"_id": 0}))
            if rules and len(rules) > 0:
                dynamic_metadata = {}
                for r in rules:
                    cat = r.get("category")
                    if cat:
                        dynamic_metadata[cat] = {
                            "description": r.get("description", ""),
                            "threat_level": r.get("threat_level", ""),
                            "action": r.get("playbook", r.get("action", ""))
                        }
                return dynamic_metadata
    except Exception as e:
        import logging
        logging.getLogger("ShieldDB").warning(f"Error fetching rules from DB: {e}. Using hardcoded fallback.")
    return CATEGORY_METADATA

@app.get("/api/categories")
def api_categories():
    """Returns definitions, threat profiles, and mitigation playbooks for the 12 safety categories."""
    return get_categories_metadata()

@app.get("/api/stats")
def api_get_stats():
    """Aggregates unified system metrics, telemetry, and blocked violations for the dashboard."""
    try:
        # Get active collections and counts
        status_info = db_status()
        
        # Calculate average latency
        latencies = api_stats["latencies"]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        # Category distribution from moderator stats
        # Create a sample breakdown to show if nothing has been recorded yet
        current_metadata = get_categories_metadata()
        cat_triggers = {cat: 0 for cat in current_metadata.keys()}
        for violation in security_violations:
            for cat in violation.get("categories", []):
                if cat in cat_triggers:
                    cat_triggers[cat] += 1
                    
        return {
            "telemetry": {
                "queries_processed": api_stats["queries_processed"],
                "blocked_queries": api_stats["blocked_queries"] + moderator.stats["blocked_requests"],
                "total_redactions": api_stats["total_redactions"],
                "avg_latency_ms": int(avg_latency),
                "active_engine": "DuoGuard-0.5B" if moderator.is_ready else "Fallback Keyword Matcher",
                "engine_ready": moderator.is_ready,
                "database_mode": "MongoMock (Sandbox)" if db_conn.is_mock else "MongoDB Atlas (Production)"
            },
            "database": {
                "collections": status_info.get("active_collections", []),
                "document_counts": status_info.get("document_counts", {})
            },
            "moderator_logs": {
                "total_inferences": moderator.stats["total_requests"],
                "local_model_hits": moderator.stats["local_inferences"],
                "fallback_hits": moderator.stats["fallback_inferences"],
            },
            "category_triggers": cat_triggers,
            "security_violations": list(reversed(security_violations))  # Return newest first
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
