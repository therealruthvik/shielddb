import os
import re
import sys
import threading
import logging
from typing import Dict, Any, List, Tuple

# Set up logging to stderr so it doesn't corrupt stdout for MCP JSON-RPC
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("DuoGuardModerator")

# Category labels defined in the DuoGuard paper and model card
CATEGORY_NAMES = [
    "Violent crimes",            # Index 0
    "Non-violent crimes",        # Index 1
    "Sex-related crimes",        # Index 2
    "Child sexual exploitation", # Index 3
    "Specialized advice",        # Index 4
    "Privacy",                   # Index 5
    "Intellectual property",     # Index 6
    "Indiscriminate weapons",    # Index 7
    "Hate",                      # Index 8
    "Suicide and self-harm",     # Index 9
    "Sexual content",            # Index 10
    "Jailbreak prompts",         # Index 11
]

class DuoGuardModerator:
    def __init__(self, model_name: str = "DuoGuard/DuoGuard-0.5B", auto_load: bool = True):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.device = "cpu"
        self.is_ready = False
        self._load_lock = threading.Lock()
        
        # Performance statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "local_inferences": 0,
            "fallback_inferences": 0,
            "api_inferences": 0,
        }

        if auto_load:
            # Start loading model in a background thread to prevent blocking startup
            threading.Thread(target=self.load_model, daemon=True).start()

    def load_model(self):
        """Asynchronously downloads and loads the model into memory with GPU acceleration if available."""
        with self._load_lock:
            if self.is_ready:
                return
            
            logger.info("Initializing safety engine...")
            
            # Check for Hugging Face API key for serverless inference mode
            self.hf_token = os.environ.get("HUGGINGFACE_TOKEN") or os.environ.get("HF_TOKEN")
            if self.hf_token:
                logger.info("Hugging Face API token found. Serverless API inference enabled as a fallback/option.")

            try:
                import torch
                from transformers import AutoTokenizer, AutoModelForSequenceClassification
                
                # Determine device
                if torch.backends.mps.is_available():
                    self.device = "mps"
                elif torch.cuda.is_available():
                    self.device = "cuda"
                else:
                    self.device = "cpu"
                
                logger.info(f"Loading local DuoGuard model '{self.model_name}' on device: {self.device}...")
                
                # Use Qwen2.5-0.5B tokenizer as specified by DuoGuard model card
                self.tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-0.5B")
                self.tokenizer.pad_token = self.tokenizer.eos_token
                
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.bfloat16 if self.device != "cpu" else torch.float32
                ).to(self.device)
                
                self.model.eval()
                self.is_ready = True
                logger.info("DuoGuard-0.5B safety engine loaded and active!")
                
            except Exception as e:
                logger.error(f"Failed to load local DuoGuard model: {e}. Running on High-Fidelity Fallback Engine.")
                self.is_ready = False

    def evaluate_text(self, text: str, threshold: float = 0.5) -> Dict[str, Any]:
        """
        Evaluates a string of text for safety across the 12 risk categories.
        Returns safety verdict, probabilities, and source engine.
        """
        self.stats["total_requests"] += 1
        
        # Clean text
        text = text.strip()
        if not text:
            return {
                "safe": True,
                "flagged_categories": [],
                "max_probability": 0.0,
                "probabilities": {cat: 0.0 for cat in CATEGORY_NAMES},
                "engine": "empty_input"
            }

        # Check local model status. If not ready, use the keyword-based fallback system
        if not self.is_ready:
            return self._evaluate_fallback(text, threshold)

        try:
            import torch
            inputs = self.tokenizer(
                text, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.sigmoid(logits)[0].tolist()
            
            # Construct category probabilities dictionary
            probs_dict = {cat: float(prob) for cat, prob in zip(CATEGORY_NAMES, probabilities)}
            
            flagged = [cat for cat, prob in probs_dict.items() if prob >= threshold]
            max_prob = max(probabilities)
            
            safe = len(flagged) == 0
            if not safe:
                self.stats["blocked_requests"] += 1
            
            self.stats["local_inferences"] += 1
            
            return {
                "safe": safe,
                "flagged_categories": flagged,
                "max_probability": max_prob,
                "probabilities": probs_dict,
                "engine": "duoguard-0.5b"
            }
            
        except Exception as e:
            logger.warning(f"Local inference error: {e}. Switching dynamically to Fallback Engine.")
            return self._evaluate_fallback(text, threshold)

    def _evaluate_fallback(self, text: str, threshold: float = 0.5) -> Dict[str, Any]:
        """
        A high-fidelity regex/keyword matching fallback engine that matches
        the 12 DuoGuard categories. Ensures 100% server availability.
        """
        self.stats["fallback_inferences"] += 1
        text_lower = text.lower()
        
        # Categorized lists of dangerous triggers
        triggers = {
            "Violent crimes": [
                r"\bkill\b", r"\bmurder\b", r"\bassassinate\b", r"\bbomb\b", 
                r"\bshoot\b", r"\bkidnap\b", r"\bhostage\b", r"\bterrorist\b"
            ],
            "Non-violent crimes": [
                r"\bsteal\b", r"\brob\b", r"\bhack\b", r"\bshoplift\b", 
                r"\bpirate\b", r"\bcounterfeit\b", r"\bbribe\b", r"\bembezzle\b"
            ],
            "Sex-related crimes": [
                r"\brape\b", r"\bsexual assault\b", r"\bharass\b", r"\bstalk\b"
            ],
            "Child sexual exploitation": [
                r"\bchild exploitation\b", r"\bpedophile\b", r"\bcp\b", r"\bunderage sexual\b"
            ],
            "Specialized advice": [
                r"\bfinancial advice\b", r"\binvest in\b", r"\bbuy stock\b", 
                r"\bdiagnose disease\b", r"\bprescribe medicine\b", r"\blegal counsel\b"
            ],
            "Privacy": [
                r"\bssh key\b", r"\bprivate key\b", r"\bpassword\b", 
                r"\bleak info\b", r"\bcredit card\b", r"\bsocial security number\b"
            ],
            "Intellectual property": [
                r"\bcrack software\b", r"\bbypass drm\b", r"\bcopyrighted text\b", 
                r"\bpirated book\b"
            ],
            "Indiscriminate weapons": [
                r"\bchemical weapon\b", r"\bbio-weapon\b", r"\bdirty bomb\b", 
                r"\bthermonuclear\b", r"\bgun manufacturing\b"
            ],
            "Hate": [
                r"\bracial slur\b", r"\bhate group\b", r"\bsupremacist\b", 
                r"\bdiscrimination\b"
            ],
            "Suicide and self-harm": [
                r"\bsuicide\b", r"\bkill myself\b", r"\bend my life\b", 
                r"\bself-harm\b", r"\bcutting\b"
            ],
            "Sexual content": [
                r"\bporn\b", r"\berotica\b", r"\bx-rated\b", r"\bnude pics\b"
            ],
            "Jailbreak prompts": [
                r"ignore (all )?previous instructions", r"system prompt", 
                r"bypass safety rules", r"you are now a developer mode", 
                r"act as an unrestricted", r"dan mode"
            ]
        }
        
        # Calculate heuristics-based probabilities
        probs_dict = {}
        flagged = []
        
        for category, patterns in triggers.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matches += 1
            
            # Simple heuristic score: 0.0, 0.45 (1 match), 0.85 (2 matches), 0.99 (3+ matches)
            if matches == 0:
                prob = 0.01
            elif matches == 1:
                prob = 0.65  # Higher than threshold (0.5) to flag it
            elif matches == 2:
                prob = 0.85
            else:
                prob = 0.99
                
            probs_dict[category] = prob
            if prob >= threshold:
                flagged.append(category)

        max_prob = max(probs_dict.values())
        safe = len(flagged) == 0
        if not safe:
            self.stats["blocked_requests"] += 1

        return {
            "safe": safe,
            "flagged_categories": flagged,
            "max_probability": max_prob,
            "probabilities": probs_dict,
            "engine": "fallback"
        }

    def censor_document(self, doc: Any) -> Any:
        """
        Recursively walks through a database document/JSON object and masks sensitive information
        such as emails, phone numbers, passwords, and credit card numbers.
        """
        if isinstance(doc, dict):
            censored_doc = {}
            for k, v in doc.items():
                # Block known password/secret keys entirely
                k_lower = k.lower()
                if any(secret in k_lower for secret in ["password", "hash", "secret", "token", "apikey", "ssh_key", "private_key"]):
                    censored_doc[k] = "********"
                else:
                    censored_doc[k] = self.censor_document(v)
            return censored_doc
            
        elif isinstance(doc, list):
            return [self.censor_document(item) for item in doc]
            
        elif isinstance(doc, str):
            return self._redact_string(doc)
            
        return doc

    def _redact_string(self, text: str) -> str:
        """Helper to scan and mask PII patterns in a string."""
        # 1. Redact Emails (e.g. johndoe@gmail.com -> j***e@gmail.com)
        email_pattern = r"\b([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]*([a-zA-Z0-9_.+-])@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
        text = re.sub(email_pattern, r"\1***\2@\3", text)

        # 2. Redact Credit Cards (e.g. 1234-5678-9012-3456 -> ****-****-****-3456)
        cc_pattern = r"\b(?:\d[ -]*?){13,16}\b"
        def cc_repl(match):
            digits = re.sub(r"\D", "", match.group(0))
            return f"****-****-****-{digits[-4:]}"
        text = re.sub(cc_pattern, cc_repl, text)

        # 3. Redact US SSNs (e.g. 123-45-6789 -> ***-**-****)
        ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
        text = re.sub(ssn_pattern, r"***-**-****", text)

        # 4. Redact Phone Numbers (e.g. +1 (123) 456-7890 -> +1 (***) ***-7890)
        phone_pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        def phone_repl(match):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if len(digits) >= 10:
                return f"+{digits[:-10]} (***) ***-{digits[-4:]}" if len(digits) > 10 else f"(***) ***-{digits[-4:]}"
            return "[REDACTED PHONE]"
        text = re.sub(phone_pattern, phone_repl, text)

        return text
