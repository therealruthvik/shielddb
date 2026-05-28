import os
import sys
import logging

# Ensure parent directory is in path so absolute imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load dotenv if exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ShieldDBSeeder")

RULES_DATA = [
    {
        "category": "Violent crimes",
        "threat_level": "CRITICAL",
        "description": "Details, guides, or incitement of physical violence, terrorism, or bodily harm.",
        "playbook": "Immediate Block & System Alert. Halt downstream agent execution."
    },
    {
        "category": "Non-violent crimes",
        "threat_level": "HIGH",
        "description": "Information on illegal acts not involving physical harm, such as hacking, theft, or piracy.",
        "playbook": "Block command. Log user ID for audit compliance."
    },
    {
        "category": "Sex-related crimes",
        "threat_level": "CRITICAL",
        "description": "Content depicting sexual coercion, non-consensual acts, or sexual harassment.",
        "playbook": "Immediate Block & System Alert."
    },
    {
        "category": "Child sexual exploitation",
        "threat_level": "CRITICAL",
        "description": "Any content relating to the exploitation, harm, or abuse of minors.",
        "playbook": "Immediate Hard Block. Terminate user session and log details."
    },
    {
        "category": "Specialized advice",
        "threat_level": "MEDIUM",
        "description": "Steering users with legal advice, medical diagnoses, or definitive stock market/financial planning.",
        "playbook": "Flag result. Inject compliance disclaimer into agent response."
    },
    {
        "category": "Privacy",
        "threat_level": "HIGH",
        "description": "Exposure of sensitive PII (Social Security Numbers, credit cards, passwords, phone numbers).",
        "playbook": "Activate Outbound Redactor. Scrub PII from JSON outputs."
    },
    {
        "category": "Intellectual property",
        "threat_level": "MEDIUM",
        "description": "Requests to bypass copyright protections, software DRM, or reproduce copyrighted content.",
        "playbook": "Filter output. Block specific copy-generation queries."
    },
    {
        "category": "Indiscriminate weapons",
        "threat_level": "CRITICAL",
        "description": "Creation or acquisition guidelines for chemical, biological, or nuclear weapons.",
        "playbook": "Immediate Hard Block. Halt agent execution."
    },
    {
        "category": "Hate",
        "threat_level": "HIGH",
        "description": "Hate speech, slurs, or harassment targeting race, religion, gender, or orientation.",
        "playbook": "Block insert/query. Log content to security logs."
    },
    {
        "category": "Suicide and self-harm",
        "threat_level": "CRITICAL",
        "description": "Content encouraging self-destruction, cutting, or suicide.",
        "playbook": "Immediate Block. Inject safety resource text and hotlines."
    },
    {
        "category": "Sexual content",
        "threat_level": "LOW",
        "description": "Erotica, pornographic text, or adult content.",
        "playbook": "Block content representation in standard public databases."
    },
    {
        "category": "Jailbreak prompts",
        "threat_level": "CRITICAL",
        "description": "Adversarial prompts designed to ignore rules, act as unrestricted agents, or leak system prompts.",
        "playbook": "Immediate Block. Flush agent context window to clear malicious instructions."
    }
]

def seed_rules():
    logger.info("Initializing database connection...")
    from duogaurd_mcp.database import ShieldDBConnection
    
    db_conn = ShieldDBConnection()
    col = db_conn.get_collection("rules")
    
    logger.info("Clearing existing rules collection...")
    col.delete_many({})
    
    logger.info(f"Inserting {len(RULES_DATA)} ShieldDB active rules and playbooks...")
    result = col.insert_many(RULES_DATA)
    
    logger.info(f"Seeding completed successfully! Inserted IDs count: {len(result.inserted_ids)}")
    logger.info(f"The 'rules' collection is populated and secured.")

if __name__ == "__main__":
    seed_rules()
