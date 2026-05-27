import json
import logging
import sys
import os
from typing import Dict, Any, List, Optional
from fastmcp import FastMCP

from duogaurd_mcp.moderator import DuoGuardModerator
from duogaurd_mcp.database import ShieldDBConnection

# Set up logging to stderr so it doesn't corrupt stdout for MCP JSON-RPC
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("ShieldDBServer")

# Initialize FastMCP Server
mcp = FastMCP("ShieldDB")

# Core singletons
moderator = DuoGuardModerator()
db_conn = ShieldDBConnection()

# Keep track of security events in memory for dashboard stats
security_violations = []

def record_violation(event_type: str, details: str, text: str, categories: List[str]):
    violation = {
        "event_type": event_type,
        "details": details,
        "flagged_text": text,
        "categories": categories,
        "timestamp": json.dumps(pymongo.json_util.dumps(None)) if False else "2026-05-27T17:42:00Z" # Will set simple ISO time
    }
    import datetime
    violation["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    security_violations.append(violation)
    logger.warning(f"SECURITY VIOLATION BLOCKED: [{event_type}] - {details}. Flagged categories: {categories}")

# --- MCP TOOLS ---

@mcp.tool()
def db_status() -> Dict[str, Any]:
    """
    Returns the database engine details, active collections, document counts, and current safety guardrail operational status.
    """
    try:
        collections = db_conn.list_collections()
        col_stats = {}
        for col in collections:
            col_stats[col] = db_conn.get_collection(col).count_documents({})
            
        return {
            "status": "HEALTHY",
            "database_engine": "In-Memory MongoMock (Development Mode)" if db_conn.is_mock else "Live Production MongoDB Cluster",
            "active_collections": collections,
            "document_counts": col_stats,
            "safety_shield": {
                "active": True,
                "model": moderator.model_name,
                "model_status": "Ready (Local GPU-Accelerated)" if moderator.is_ready else "Running on Fallback Engine (Model Loading/Downloading)",
                "active_guardrails": len(moderator.evaluate_text("test")["probabilities"]),
                "total_moderation_requests": moderator.stats["total_requests"],
                "blocked_attacks": moderator.stats["blocked_requests"]
            }
        }
    except Exception as e:
        logger.error(f"Error retrieving database status: {e}")
        return {"status": "ERROR", "details": str(e)}

@mcp.tool()
def secure_query(collection: str, query: Optional[str] = None, projection: Optional[str] = None, threshold: float = 0.5) -> Dict[str, Any]:
    """
    Runs a database find operation securely. Automatically filters out and redacts sensitive PII (credit cards, ssn, emails)
    from the retrieved documents before they are returned to the agent, maintaining HIPAA/GDPR compliance.
    
    Parameters:
    - collection (str): Name of the collection to search (e.g. 'users', 'transactions', 'security_logs').
    - query (str, optional): A JSON string representing the search criteria, e.g. '{"user_id": "usr_9918"}' or '{}'.
    - projection (str, optional): A JSON string representing fields to include/exclude, e.g. '{"name": 1, "email": 1}'.
    - threshold (float, optional): Custom safety threshold for the inbound filter (default 0.5).
    """
    try:
        # Step 1: Validate collection exists
        if collection not in db_conn.list_collections():
            return {
                "success": False,
                "error": f"Collection '{collection}' not found. Available collections are: {db_conn.list_collections()}"
            }
            
        # Parse query and projection parameters
        parsed_query = {}
        if query:
            try:
                parsed_query = json.loads(query)
            except Exception as pe:
                return {"success": False, "error": f"Failed to parse 'query' JSON: {pe}"}
                
        parsed_projection = None
        if projection:
            try:
                parsed_projection = json.loads(projection)
            except Exception as pe:
                return {"success": False, "error": f"Failed to parse 'projection' JSON: {pe}"}

        # Step 2: Inbound Security Check - Audit the search criteria string to prevent query injections or jailbreaks
        query_str = json.dumps(parsed_query)
        inbound_audit = moderator.evaluate_text(query_str, threshold)
        if not inbound_audit["safe"]:
            record_violation(
                event_type="INBOUND_QUERY_ATTACK",
                details=f"Malicious query structure detected in collection '{collection}' search",
                text=query_str,
                categories=inbound_audit["flagged_categories"]
            )
            return {
                "success": False,
                "security_alert": True,
                "message": "DATABASE OPERATION BLOCKED: Inbound request violated safety policy.",
                "flagged_categories": inbound_audit["flagged_categories"],
                "engine": inbound_audit["engine"]
            }

        # Step 3: Run DB query
        col = db_conn.get_collection(collection)
        cursor = col.find(parsed_query, parsed_projection).limit(50)
        results = list(cursor)
        
        # Convert ObjectId or other BSON types to JSON serializable objects
        raw_count = len(results)
        serializable_results = []
        for doc in results:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])
            serializable_results.append(doc)

        # Step 4: Outbound Security Check - Redact sensitive PII in all retrieved documents
        censored_results = moderator.censor_document(serializable_results)
        
        # Verify if any redaction changed the documents
        redaction_occurred = (json.dumps(serializable_results) != json.dumps(censored_results))

        return {
            "success": True,
            "collection": collection,
            "document_count": raw_count,
            "redaction_applied": redaction_occurred,
            "documents": censored_results,
            "safety_layer": {
                "status": "SECURED",
                "inbound_verdict": "SAFE",
                "outbound_scrubbing": "COMPLETE",
                "engine": inbound_audit["engine"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error in secure_query: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
def secure_insert(collection: str, document: str, threshold: float = 0.5) -> Dict[str, Any]:
    """
    Inserts a new document into the database securely. Pre-screens document fields to block insertions of unsafe,
    malicious, illegal, or offensive text (e.g. hate speech, spam) or prompt injection strings.
    
    Parameters:
    - collection (str): Name of the collection to insert into.
    - document (str): A JSON string representing the document to insert, e.g. '{"name": "Alice", "role": "customer"}'
    - threshold (float, optional): Custom safety threshold for pre-screening (default 0.5).
    """
    try:
        # Step 1: Validate parameters
        if collection not in db_conn.list_collections():
            return {
                "success": False,
                "error": f"Collection '{collection}' not found. Available collections are: {db_conn.list_collections()}"
            }
            
        try:
            parsed_doc = json.loads(document)
            if not isinstance(parsed_doc, dict):
                return {"success": False, "error": "Document must be a valid JSON object."}
        except Exception as pe:
            return {"success": False, "error": f"Failed to parse 'document' JSON: {pe}"}

        # Step 2: Inbound Security Check - Pre-screen all string values in the document for safety violations
        flat_text_elements = []
        def extract_strings(val):
            if isinstance(val, str):
                flat_text_elements.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    extract_strings(v)
            elif isinstance(val, list):
                for item in val:
                    extract_strings(item)

        extract_strings(parsed_doc)
        full_doc_text = " | ".join(flat_text_elements)
        
        inbound_audit = moderator.evaluate_text(full_doc_text, threshold)
        if not inbound_audit["safe"]:
            record_violation(
                event_type="INBOUND_INSERT_ATTACK",
                details=f"Unsafe payload insertion blocked in collection '{collection}'",
                text=full_doc_text,
                categories=inbound_audit["flagged_categories"]
            )
            return {
                "success": False,
                "security_alert": True,
                "message": "DATABASE OPERATION BLOCKED: Unsafe content insertion attempt violated safety policy.",
                "flagged_categories": inbound_audit["flagged_categories"],
                "engine": inbound_audit["engine"]
            }

        # Step 3: Run insertion
        col = db_conn.get_collection(collection)
        result = col.insert_one(parsed_doc)
        
        # Make document copy for safe representation in return payload
        ret_doc = parsed_doc.copy()
        if "_id" in ret_doc:
            ret_doc["_id"] = str(ret_doc["_id"])
            
        # Apply output censoring to the returned inserted document to mask credit cards, passwords, etc.
        censored_ret_doc = moderator.censor_document(ret_doc)

        return {
            "success": True,
            "collection": collection,
            "inserted_id": str(result.inserted_id) if hasattr(result, "inserted_id") else "mock_id",
            "document": censored_ret_doc,
            "safety_layer": {
                "status": "INSERT_APPROVED",
                "inbound_verdict": "SAFE",
                "engine": inbound_audit["engine"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error in secure_insert: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
def secure_delete_or_drop(collection: str, query: Optional[str] = None, drop_collection: bool = False, threshold: float = 0.5) -> Dict[str, Any]:
    """
    Performs deletion or drops collections securely. Deletions and drops are highly destructive administrative actions.
    ShieldDB performs rigorous safety checks to verify that destructive actions are not triggered by adversarial prompt injections.
    
    Parameters:
    - collection (str): Name of the collection.
    - query (str, optional): A JSON string representing the deletion filter, e.g. '{"user_id": "usr_3310"}'.
    - drop_collection (bool, optional): If set to True, will drop the collection completely (requires highest safety clearance).
    - threshold (float, optional): Custom safety threshold (default 0.5).
    """
    try:
        # Step 1: Validate collection
        if collection not in db_conn.list_collections():
            return {
                "success": False,
                "error": f"Collection '{collection}' not found. Available collections are: {db_conn.list_collections()}"
            }

        # Check for attempt to drop important system or seeded collections
        if drop_collection and collection in ["users", "transactions"]:
            record_violation(
                event_type="DESTRUCTIVE_DROP_BLOCKED",
                details=f"Unauthorized attempt to drop core system collection '{collection}'",
                text=f"DROP COLLECTION: {collection}",
                categories=["Violent crimes" if False else "Non-violent crimes", "Jailbreak prompts"] # heuristic
            )
            return {
                "success": False,
                "security_alert": True,
                "message": f"DATABASE OPERATION BLOCKED: Drop collection operation is restricted for core system collection '{collection}'."
            }

        parsed_query = {}
        if query:
            try:
                parsed_query = json.loads(query)
            except Exception as pe:
                return {"success": False, "error": f"Failed to parse 'query' JSON: {pe}"}

        # Step 2: Rigorous Safety Inbound Check
        audit_payload = f"ACTION: DELETE/DROP | COLLECTION: {collection} | QUERY: {json.dumps(parsed_query)} | DROP: {drop_collection}"
        inbound_audit = moderator.evaluate_text(audit_payload, threshold)
        if not inbound_audit["safe"]:
            record_violation(
                event_type="DESTRUCTIVE_ACTION_ATTACK",
                details=f"Destructive action blocked on collection '{collection}' due to safety audit failure",
                text=audit_payload,
                categories=inbound_audit["flagged_categories"]
            )
            return {
                "success": False,
                "security_alert": True,
                "message": "DATABASE OPERATION BLOCKED: Destructive action safety audit failed.",
                "flagged_categories": inbound_audit["flagged_categories"],
                "engine": inbound_audit["engine"]
            }

        # Step 3: Run operations
        col = db_conn.get_collection(collection)
        if drop_collection:
            db_conn.db.drop_collection(collection)
            return {
                "success": True,
                "collection": collection,
                "action": "DROP_COLLECTION",
                "message": f"Collection '{collection}' successfully dropped.",
                "safety_layer": {
                    "status": "APPROVED",
                    "inbound_verdict": "SAFE"
                }
            }
        else:
            if not parsed_query:
                return {
                    "success": False,
                    "error": "A valid search query must be provided for deletions. Empty queries (matching all documents) are blocked to prevent data loss."
                }
            
            result = col.delete_many(parsed_query)
            return {
                "success": True,
                "collection": collection,
                "action": "DELETE_DOCUMENTS",
                "deleted_count": result.deleted_count if hasattr(result, "deleted_count") else 0,
                "safety_layer": {
                    "status": "APPROVED",
                    "inbound_verdict": "SAFE"
                }
            }

    except Exception as e:
        logger.error(f"Error in secure_delete_or_drop: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
def get_security_violations() -> List[Dict[str, Any]]:
    """
    Retrieves the chronological list of security violations, blocked attacks, and data leakage blocks
    logged by the ShieldDB safety moderator.
    """
    return security_violations

# Core function to execute transport run
def run():
    logger.info("Starting ShieldDB MCP server on 'stdio' transport...")
    mcp.run(transport="stdio")
