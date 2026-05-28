import os
import sys
import logging
from typing import Dict, Any, List
import pymongo
import mongomock

logger = logging.getLogger("ShieldDB")

class ShieldDBConnection:
    def __init__(self, uri: str = None):
        self.uri = uri or os.environ.get("MONGODB_URI") or os.environ.get("MONGO_URI")
        self.client = None
        self.db = None
        self.is_mock = False
        
        self.connect()
        self.seed_sample_data()

    def connect(self):
        """Attempts to connect to MongoDB. Falls back to an in-memory mongomock if unavailable."""
        if self.uri:
            try:
                logger.info(f"Attempting connection to live MongoDB instance: {self.uri.split('@')[-1]}...")
                # Connect with a short timeout so it fails quickly if unavailable
                self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=2000)
                # Trigger a call to verify connection
                self.client.server_info()
                self.db = self.client.get_database("shield_db")
                self.is_mock = False
                logger.info("Connected to live MongoDB successfully!")
                return
            except Exception as e:
                logger.warning(f"Failed to connect to live MongoDB: {e}. Falling back to In-Memory MongoMock.")
        else:
            logger.info("No MONGODB_URI environment variable detected. Activating In-Memory MongoMock database.")
            
        self.client = mongomock.MongoClient()
        self.db = self.client.shield_db
        self.is_mock = True
        logger.info("In-Memory MongoMock database initialized and active.")

    def seed_sample_data(self):
        """Seeds sample mock data for testing and playground demonstrations if the DB is empty."""
        try:
            # Seed users
            if "users" not in self.db.list_collection_names() or self.db.users.count_documents({}) == 0:
                logger.info("Seeding sample customer records...")
                self.db.users.insert_many([
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
                ])
                
            # Seed transactions
            if "transactions" not in self.db.list_collection_names() or self.db.transactions.count_documents({}) == 0:
                self.db.transactions.insert_many([
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
                ])
                
            # Seed security logs
            if "security_logs" not in self.db.list_collection_names() or self.db.security_logs.count_documents({}) == 0:
                self.db.security_logs.insert_many([
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
                ])
                
            # Seed rules
            if "rules" not in self.db.list_collection_names() or self.db.rules.count_documents({}) == 0:
                self.db.rules.insert_many([
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
                ])
                
            logger.info("Sample database seeding completed successfully!")
        except Exception as e:
            logger.error(f"Error seeding database: {e}")
            
    def get_collection(self, name: str):
        return self.db[name]

    def list_collections(self) -> List[str]:
        return self.db.list_collection_names()
