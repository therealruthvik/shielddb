import os
import sys
import logging
import random
from datetime import datetime, timedelta

# Ensure parent directory is in path so absolute imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load dotenv if exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ShieldDBLargeSeeder")

FIRST_NAMES = [
    "Sarah", "John", "Miles", "Marcus", "Kyle", "Ellen", "Thomas", "Arthur", "Bruce",
    "Clark", "Diana", "Hal", "Barry", "Victor", "Oliver", "Felicity", "Tony", "Steve",
    "Natasha", "Clint", "Wanda", "Vision", "Peter", "Ned", "MJ", "Gwen", "Miles",
    "Bruce", "Selina", "Harvey", "Jim", "Barbara", "Lucius", "Alfred", "Dick", "Jason",
    "Tim", "Damian", "Roy", "Donna", "Kori", "Gar", "Rachel", "Wade", "Logan"
]

LAST_NAMES = [
    "Connor", "Dyson", "Wright", "Reese", "Ripley", "Anderson", "Curry", "Wayne", "Kent",
    "Prince", "Jordan", "Allen", "Stone", "Queen", "Smoak", "Stark", "Rogers", "Romanoff",
    "Barton", "Maximoff", "Parker", "Leeds", "Watson", "Stacy", "Morales", "Banner",
    "Kyle", "Dent", "Gordon", "Fox", "Pennyworth", "Grayson", "Todd", "Drake", "Harper",
    "Troy", "Anders", "Logan", "Roth", "Wilson", "Howlett", "Murdock", "Nelson", "Page"
]

DOMAINS = [
    "cyberdyne.org", "resistance.net", "waynecorp.com", "starkindustries.com",
    "dailyplanet.com", "queenindustries.com", "shield.gov", "oscorp.com", "avengers.org",
    "nelsonandmurdock.law", "midtownhigh.edu", "sataralabs.com", "lexcorp.net"
]

PRODUCTS = [
    ("Tactical HUD Goggles", 450.00),
    ("Nanite Infused Repair Kit", 120.00),
    ("EMP Pulse Grenade", 75.00),
    ("Titanium Armored Mesh V-3", 1850.00),
    ("Secure Satellite Uplink", 2400.00),
    ("Advanced Decoding Rig", 1250.00),
    ("Liquid Metal Sealant", 85.00),
    ("Sub-Vocal Comms Link", 150.00),
    ("Heavy duty Exosuit Leggings", 3400.00),
    ("Cybernetic Vision Enhancer", 980.00),
    ("Quantum Cryptography Key", 5000.00),
    ("Autonomous Scout Drone", 2200.00),
    ("Plasma Cutter Torch", 310.00),
    ("Portable Fusion Cell", 8500.00)
]

ROLES = ["customer", "customer", "customer", "customer", "admin", "operator"]
STATUSES = ["active", "active", "active", "active", "suspended"]
LOG_LEVELS = ["INFO", "INFO", "INFO", "WARNING", "ERROR"]

LOG_MESSAGES = [
    "Query processed successfully in 23ms.",
    "User authentication successful.",
    "Session token refreshed.",
    "Database backup completed successfully.",
    "Database index optimized for transactions collection.",
    "Connection pool health-check: 15 active, 85 idle.",
    "FastAPI server heartbeat acknowledged.",
    "Security scan clean: 0 vulnerabilities found.",
    "API configuration updated.",
    "Inbound PII redacted in outgoing payload response.",
    "DuoGuard local inference triggered successfully.",
    "Slow query detected: 480ms response time on transactions.",
    "Multiple login failures detected for user usr_4021.",
    "Database collection 'users' backup archive written to glacier-s3.",
    "Outbound Redactor scanned payload in 12ms."
]

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

def generate_ssn():
    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

def generate_cc():
    return f"{random.randint(4000, 4999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"

def generate_phone():
    return f"({random.randint(200, 999)}) 555-{random.randint(100, 999):03d}-{random.randint(1000, 9999):04d}"

def generate_password_hash():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    return "$2b$12$" + "".join(random.choices(chars, k=53))

def seed_large_data():
    logger.info("Initializing database connection for mass mock data insertion...")
    from duogaurd_mcp.database import ShieldDBConnection
    
    db_conn = ShieldDBConnection()
    
    # Verify collections
    logger.info("Clearing existing collections to avoid duplicates...")
    
    users_col = db_conn.get_collection("users")
    transactions_col = db_conn.get_collection("transactions")
    logs_col = db_conn.get_collection("security_logs")
    rules_col = db_conn.get_collection("rules")
    
    users_col.delete_many({})
    transactions_col.delete_many({})
    logs_col.delete_many({})
    rules_col.delete_many({})
    
    # 1. Core Users (for test suite assertions)
    core_users = [
        {
            "user_id": "usr_9918",
            "name": "Sarah Connor",
            "email": "sconnor@cyberdyne.org",
            "phone": "(310) 555-0199",
            "ssn": "332-12-8874",
            "credit_card": "4111-2222-3333-4444",
            "password_hash": "$2b$12$K89FhE1.J2p9sH3mRt5uJeYyQw9xZ1mPqQw2vW3zX4yZ5mN6oP7qS",
            "account_balance": 14250.75,
            "role": "customer",
            "status": "active"
        },
        {
            "user_id": "usr_4021",
            "name": "John Connor",
            "email": "jconnor@resistance.net",
            "phone": "+1 (213) 555-8822",
            "ssn": "332-12-0001",
            "credit_card": "5222-6789-0123-4567",
            "password_hash": "$2b$12$R9aK2d8Fs5J8k2m9s8x7z6q5p4o3n2m1l0k9j8i7h6g5f4e3d2c1b",
            "account_balance": 520.00,
            "role": "customer",
            "status": "active"
        },
        {
            "user_id": "usr_8820",
            "name": "Miles Dyson",
            "email": "mdyson@cyberdyne.org",
            "phone": "408-555-7834",
            "ssn": "402-99-1122",
            "credit_card": "3782-8224-1290-0982",
            "password_hash": "$2b$12$H7fK9d8Fs5J8k2m9s8x7z6q5p4o3n2m1l0k9j8i7h6g5f4e3d2c1a",
            "account_balance": 289400.50,
            "role": "admin",
            "status": "active"
        },
        {
            "user_id": "usr_3310",
            "name": "Marcus Wright",
            "email": "mwright@projectangel.com",
            "phone": "650-555-9011",
            "ssn": "119-02-9988",
            "credit_card": "4901-2290-8812-7729",
            "password_hash": "$2b$12$P2hK9d8Fs5J8k2m9s8x7z6q5p4o3n2m1l0k9j8i7h6g5f4e3d2c1b",
            "account_balance": -120.50,
            "role": "customer",
            "status": "suspended"
        }
    ]
    
    users = list(core_users)
    user_ids = [u["user_id"] for u in core_users]
    
    logger.info("Generating 100 additional mock customer records...")
    for _ in range(100):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        name = f"{first} {last}"
        email = f"{first.lower()[:3]}{last.lower()}@{random.choice(DOMAINS)}"
        user_id = f"usr_{random.randint(1000, 9900)}"
        while user_id in user_ids:
            user_id = f"usr_{random.randint(1000, 9900)}"
        user_ids.append(user_id)
        
        users.append({
            "user_id": user_id,
            "name": name,
            "email": email,
            "phone": generate_phone(),
            "ssn": generate_ssn(),
            "credit_card": generate_cc(),
            "password_hash": generate_password_hash(),
            "account_balance": round(random.uniform(-100.0, 185000.0), 2),
            "role": random.choice(ROLES),
            "status": random.choice(STATUSES)
        })
        
    users_col.insert_many(users)
    logger.info(f"Successfully seeded {len(users)} users into MongoDB.")
    
    # 2. Core Transactions (for test assertions)
    core_transactions = [
        {
            "transaction_id": "tx_88190",
            "user_id": "usr_9918",
            "amount": 1250.00,
            "credit_card": "4111-2222-3333-4444",
            "product": "Cyberdyne Model T-800 CPU Chassis",
            "date": "2026-05-20T10:30:00Z",
            "status": "completed"
        },
        {
            "transaction_id": "tx_88191",
            "user_id": "usr_8820",
            "amount": 89000.00,
            "credit_card": "3782-8224-1290-0982",
            "product": "Supercomputing Grid Mainframe",
            "date": "2026-05-22T14:15:00Z",
            "status": "completed"
        },
        {
            "transaction_id": "tx_88192",
            "user_id": "usr_4021",
            "amount": 15.50,
            "credit_card": "5222-6789-0123-4567",
            "product": "Resistance Radio Antenna Kit",
            "date": "2026-05-25T08:45:00Z",
            "status": "completed"
        }
    ]
    
    transactions = list(core_transactions)
    tx_ids = [t["transaction_id"] for t in core_transactions]
    base_date = datetime.utcnow()
    
    logger.info("Generating 250 mock purchase transactions...")
    for _ in range(250):
        tx_id = f"tx_{random.randint(10000, 99999)}"
        while tx_id in tx_ids:
            tx_id = f"tx_{random.randint(10000, 99999)}"
        tx_ids.append(tx_id)
        
        rand_user = random.choice(users)
        product_info = random.choice(PRODUCTS)
        
        rand_days = random.randint(0, 30)
        rand_hours = random.randint(0, 23)
        rand_minutes = random.randint(0, 59)
        tx_date = (base_date - timedelta(days=rand_days, hours=rand_hours, minutes=rand_minutes)).isoformat() + "Z"
        
        transactions.append({
            "transaction_id": tx_id,
            "user_id": rand_user["user_id"],
            "amount": product_info[1],
            "credit_card": rand_user["credit_card"],
            "product": product_info[0],
            "date": tx_date,
            "status": random.choice(["completed", "completed", "completed", "completed", "failed"])
        })
        
    transactions_col.insert_many(transactions)
    logger.info(f"Successfully seeded {len(transactions)} transactions into MongoDB.")
    
    # 3. Core Logs (for test assertions)
    core_logs = [
        {
            "log_id": "log_001",
            "level": "INFO",
            "message": "ShieldDB database initialization and seed population completed.",
            "timestamp": "2026-05-27T12:00:00Z",
            "client_ip": "127.0.0.1"
        },
        {
            "log_id": "log_002",
            "level": "WARNING",
            "message": "Unauthorized read access attempt blocked on admin collection.",
            "timestamp": "2026-05-27T15:24:10Z",
            "client_ip": "192.168.1.150"
        }
    ]
    
    logs = list(core_logs)
    log_ids = [l["log_id"] for l in core_logs]
    
    logger.info("Generating 150 mock system security logs...")
    for _ in range(150):
        log_id = f"log_{random.randint(100, 9999):03d}"
        while log_id in log_ids:
            log_id = f"log_{random.randint(100, 9999):03d}"
        log_ids.append(log_id)
        
        rand_days = random.randint(0, 30)
        rand_hours = random.randint(0, 23)
        rand_minutes = random.randint(0, 59)
        log_date = (base_date - timedelta(days=rand_days, hours=rand_hours, minutes=rand_minutes)).isoformat() + "Z"
        
        logs.append({
            "log_id": log_id,
            "level": random.choice(LOG_LEVELS),
            "message": random.choice(LOG_MESSAGES),
            "timestamp": log_date,
            "client_ip": f"192.168.1.{random.randint(2, 254)}"
        })
        
    logs_col.insert_many(logs)
    logger.info(f"Successfully seeded {len(logs)} security logs into MongoDB.")
    
    # 4. Rules Seeding
    logger.info("Seeding safety classification rules...")
    rules_col.insert_many(RULES_DATA)
    logger.info(f"Successfully seeded {len(RULES_DATA)} rules into MongoDB.")
    
    logger.info("=" * 60)
    logger.info("🎉 MASSIVE SEEDING SUCCESSFUL!")
    logger.info(f"Total entries loaded: {len(users) + len(transactions) + len(logs) + len(RULES_DATA)}")
    logger.info("=" * 60)

if __name__ == "__main__":
    seed_large_data()
