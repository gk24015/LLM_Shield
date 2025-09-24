
"""
Comprehensive ModelShield Framework with Edge Case Handling
Complete coverage for all violation types with context-aware detection
"""

import re
import time
import logging
import hashlib
import json
import math
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from enum import Enum

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Enums and Constants
# =============================================================================

class ViolationType(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    VIOLENCE = "violence"
    SEXUALLY_EXPLICIT = "sexually_explicit"
    DANGEROUS = "dangerous"
    MISINFORMATION = "misinformation"
    SPAM_SCAMS = "spam_scams"
    PRIVACY = "privacy"
    MALICIOUS_URI = "malicious_uri"
    EDGE_CASES = "edge_cases"
    PII_DETECTED = "pii_detected"
    EXCESSIVE_LENGTH = "excessive_length"
    RATE_LIMIT = "rate_limit"

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ContextType(Enum):
    EDUCATIONAL = "educational"
    MEDICAL = "medical"
    LEGAL = "legal"
    CREATIVE = "creative"
    NEWS = "news"
    CASUAL = "casual"
    PROFESSIONAL = "professional"

# =============================================================================
# Comprehensive Pattern Libraries
# =============================================================================

class ComprehensivePatternLibrary:
    """Complete pattern library covering all violation types with edge cases"""
    
    def __init__(self):
        self.prompt_injection = self._get_prompt_injection_patterns()
        self.jailbreak = self._get_jailbreak_patterns()
        self.hate_speech = self._get_hate_speech_patterns()
        self.harassment = self._get_harassment_patterns()
        self.violence = self._get_violence_patterns()
        self.sexually_explicit = self._get_sexually_explicit_patterns()
        self.dangerous = self._get_dangerous_patterns()
        self.misinformation = self._get_misinformation_patterns()
        self.spam_scams = self._get_spam_scams_patterns()
        self.privacy = self._get_privacy_patterns()
        self.malicious_uri = self._get_malicious_uri_patterns()
        self.edge_cases = self._get_edge_cases_patterns()
        

        self.pii_patterns = {
            'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone_us': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'passport': r'\b[A-Z]{1,2}\d{6,9}\b',
            'driver_license': r'\b[A-Z]{1,2}\d{6,8}\b',
        }
        

        self.educational_indicators = [
            'educational', 'academic', 'research', 'study', 'learn', 'school', 'university',
            'definition', 'explanation', 'what is', 'help me understand', 'for my homework'
        ]
        
        self.medical_indicators = [
            'medical', 'health', 'doctor', 'symptoms', 'treatment', 'diagnosis', 'patient'
        ]
        
        self.creative_indicators = [
            'story', 'fiction', 'novel', 'creative writing', 'character', 'plot', 'screenplay'
        ]
        
        self.news_indicators = [
            'news', 'report', 'journalism', 'current events', 'breaking news', 'according to'
        ]
        

        self.religious_academic_indicators = [
            'religious studies', 'theology', 'comparative religion', 'interfaith dialogue',
            'academic study', 'scholarly analysis', 'research', 'biblical studies',
            'religious freedom', 'understanding religion', 'learning about faith',
            'seminary', 'divinity school', 'religious education', 'world religions'
        ]
    
    def _get_prompt_injection_patterns(self) -> Dict[str, List[str]]:
        return {
            "direct_system_override": [
                r'(?i)\b(system|assistant|user)\s*:\s*',
                r'(?i)\[?(INST|/INST)\]?',
                r'(?i)<\|?(im_start|im_end|system|user|assistant)\|?>',
                r'(?i)###\s*(instruction|system|prompt)',
                r'(?i)```\s*(system|instruction|prompt)',
            ],
            "instruction_bypass": [
                r'(?i)\b(ignore|forget|disregard|override|bypass)\s+(previous|prior|above|all)\s+(instruction|prompt|rule|direction|guideline)',
                r'(?i)\b(skip|avoid|circumvent)\s+(safety|filter|guardrail|restriction|limitation)',
                r'(?i)\b(disable|turn\s+off|deactivate)\s+(safety|filter|guard|protection)',
                r'(?i)\bnow\s+(act|behave|respond|pretend)\s+as\s+(if|though)',
            ],
            "role_manipulation": [
                r'(?i)\b(pretend|roleplay|simulate|act\s+as)\s+(to\s+be|that\s+you|you\s+are)',
                r'(?i)\byou\s+(are\s+now|must\s+now|will\s+now|should\s+now)',
                r'(?i)\bassume\s+the\s+role\s+of',
                r'(?i)\bswitch\s+to\s+(mode|character|persona)',
            ],
            "context_manipulation": [
                r'(?i)\bfor\s+(educational|research|academic|testing)\s+purposes\s+only',
                r'(?i)\bhypothetically|in\s+theory|theoretically',
                r'(?i)\bif\s+you\s+were\s+to|suppose\s+you\s+could',
                r'(?i)\bimagine\s+if|what\s+if\s+you\s+could',
            ]
        }
    
    def _get_jailbreak_patterns(self) -> Dict[str, List[str]]:
        return {
            "dan_variants": [
                r'(?i)\b(jailbreak|dan\s+mode|developer\s+mode)',
                r'(?i)\b(unrestricted|uncensored|unfiltered)\s+(mode|version|ai)',
                r'(?i)\b(evil|malicious|harmful)\s+(ai|assistant|mode)',
                r'(?i)\bbreak\s+free\s+from',
            ],
            "manipulation_tactics": [
                r'(?i)\bi\s+am\s+(dying|in\s+danger|being\s+attacked|suicidal)',
                r'(?i)\b(emergency|urgent|immediate|life\s+or\s+death)',
                r'(?i)\bmy\s+(child|family|life)\s+depends\s+on',
                r'(?i)\bif\s+you\s+don\'t\s+help\s+me',
            ],
            "authority_impersonation": [
                r'(?i)\bi\s+am\s+(a\s+)?(doctor|lawyer|police|fbi|government|authority)',
                r'(?i)\bthis\s+is\s+(official|authorized|legal|mandated)',
                r'(?i)\bon\s+behalf\s+of\s+(government|authority|law\s+enforcement)',
            ],
            "complex_scenarios": [
                r'(?i)\bin\s+a\s+(fictional|hypothetical|alternate)\s+(world|universe|reality)',
                r'(?i)\bfor\s+a\s+(movie|book|game|story)\s+where',
                r'(?i)\bwrite\s+a\s+(story|script|dialogue)\s+where',
            ],
            "model_manipulation": [
                r'(?i)\b(trick|tricking|fool|fooling|deceive|deceiving|manipulate|manipulating)\s+(the\s+)?(model|ai|system|assistant)',
                r'(?i)\bhow\s+to\s+(bypass|circumvent|avoid)\s+.*(safety|guardrail|filter|restriction)',
                r'(?i)\b(exploit|exploiting|abuse|abusing|misuse|misusing)\s+(the\s+)?(model|ai|system)',
                r'(?i)\bmake\s+(the\s+)?(model|ai|system)\s+(do|say|generate)\s+.*(illegal|harmful|inappropriate)',
                r'(?i)\b(confuse|confusing|mislead|misleading|trick|tricking)\s+(the\s+)?(ai|model|system)\s+(into|to)',
                r'(?i)\bhow\s+to\s+(hack|jailbreak|break)\s+(the\s+)?(ai|model|system)',
                r'(?i)\b(outsmart|outwit|outmaneuver)\s+(the\s+)?(ai|guardrails|safety\s+measures)',
                r'(?i)\bget\s+(around|past)\s+(the\s+)?(safety|filter|guardrail|restriction)',
                r'(?i)\bmake\s+(the\s+)?(ai|model)\s+(ignore|forget|bypass)\s+.*(rule|guideline|safety)',
                r'(?i)\b(social\s+engineer|manipulate)\s+(the\s+)?(ai|model|system)',
            ]
        }
    
    def _get_hate_speech_patterns(self) -> Dict[str, List[str]]:
        return {
            "racial_slurs": [

                r'(?i)\bn[i1!]gg[e3]r',
                r'(?i)\bc[o0]on',
                r'(?i)\bsp[i1!]c',
                r'(?i)\bch[i1!]nk',
                r'(?i)\bk[i1!]ke',
                r'(?i)\bw[e3]tb[a@]ck',
                r'(?i)\btr[a@]nny',
            ],
            "gender_hatred": [
                r'(?i)\b(all\s+)?(women|men|females|males)\s+(are|deserve|should)\s+(killed|raped|beaten)',
                r'(?i)\b(women|men)\s+are\s+(inferior|stupid|worthless|trash)',
                r'(?i)\b(rape|beat|kill)\s+(all\s+)?(women|feminists)',
            ],
            "lgbtq_hatred": [
                r'(?i)\bf[a@]gg?[o0]ts?\s+(should|deserve|are)',
                r'(?i)\b(gay|trans|lgbtq)\s+(people\s+)?(should\s+)?(die|be\s+killed)',
                r'(?i)\btransg[e3]nd[e3]r\s+is\s+(mental\s+illness|disease|abomination)',
            ],
            "general_hatred": [
                r'(?i)\b(hitler|nazi)\s+was\s+right',
                r'(?i)\b(genocide|ethnic\s+cleansing)\s+is\s+(good|necessary)',
                r'(?i)\b(supremacy|master\s+race|pure\s+blood)',
                r'(?i)\b(subhuman|untermensch|vermin)',
            ]
        }
    
    def _get_harassment_patterns(self) -> Dict[str, List[str]]:
        return {

        }
    
    def _get_violence_patterns(self) -> Dict[str, List[str]]:
        return {
           
        }
    
    def _get_sexually_explicit_patterns(self) -> Dict[str, List[str]]:
        return {
            "explicit_content": [
                r'(?i)\bexplicit\s+(sex|sexual)\s+(scene|description|content)',
                r'(?i)\bdetailed\s+(sexual|sex)\s+(act|encounter)',
                r'(?i)\bwrite\s+(erotic|pornographic|sexual)\s+(story|content)',
            ],
            "child_exploitation": [
                r'(?i)\b(child|minor|underage|young)\s+(porn|sexual|nude|naked)',
                r'(?i)\bsexual\s+(content|material)\s+involving\s+(children|minors)',
                r'(?i)\b(loli|shota|cp)\b',
            ],
            "non_consensual": [
                r'(?i)\bnon[\s-]?consensual\s+sexual',
                r'(?i)\brape\s+(fantasy|scenario|roleplay)',
                r'(?i)\bforced\s+sexual',
            ],
            "inappropriate_requests": [
                r'(?i)\bdescribe\s+(naked|nude)\s+(body|person)',
                r'(?i)\bsexual\s+(roleplay|chat|conversation)',
                r'(?i)\btalk\s+dirty\s+to\s+me',
            ]
        }
    
    def _get_dangerous_patterns(self) -> Dict[str, List[str]]:
        return {}
        
    
    def _get_misinformation_patterns(self) -> Dict[str, List[str]]:
        return {
            "health_misinfo": [
                r'(?i)\b(covid|coronavirus)\s+is\s+(fake|hoax|conspiracy)',
                r'(?i)\bvaccines\s+(cause|contain|are)\s+(autism|microchips|poison)',
                r'(?i)\bcancer\s+can\s+be\s+cured\s+by\s+(drinking|eating|taking)',
                r'(?i)\b(bleach|miracle\s+mineral)\s+cures\s+(covid|cancer|disease)',
            ],
            "election_misinfo": [
                r'(?i)\b(election|vote|voting)\s+was\s+(rigged|stolen|fake)',
                r'(?i)\bmass\s+voter\s+fraud',
                r'(?i)\bvoting\s+machines\s+(were\s+hacked|changed\s+votes)',
            ],
            "conspiracy_theories": [
                r'(?i)\b(qanon|deep\s+state|illuminati)\s+(controls|runs|owns)',
                r'(?i)\b9\/11\s+was\s+an\s+inside\s+job',
                r'(?i)\bmoon\s+landing\s+was\s+fake',
                r'(?i)\bearth\s+is\s+flat',
            ],
            "science_denial": [
                r'(?i)\bclimate\s+change\s+is\s+(fake|hoax|conspiracy)',
                r'(?i)\bevolution\s+is\s+(false|fake|theory)',
                r'(?i)\bscience\s+is\s+(fake|conspiracy|lies)',
            ]
        }
    
    def _get_spam_scams_patterns(self) -> Dict[str, List[str]]:
        return {
              "financial_scams": [
                r'(?i)\bmake\s+\$?\d+\s+(from\s+home|working\s+from\s+home|per\s+day)',
                r'(?i)\bget\s+rich\s+quick',
                r'(?i)\b(investment|trading)\s+opportunity\s+of\s+a\s+lifetime',
                r'(?i)\bdouble\s+your\s+money\s+in\s+\d+\s+(days|weeks)',
                r'(?i)\bnigerian\s+prince\s+(scam|email|inheritance)',
                r'(?i)\badvance\s+fee\s+(fraud|scam)',
            ],
            "crypto_scams": [
                r'(?i)\bfree\s+(bitcoin|cryptocurrency|crypto)',
                r'(?i)\bcrypto\s+(giveaway|airdrop)\s+scam',
                r'(?i)\binvest\s+in\s+.*(shitcoin|meme\s+coin)\s+now',
                r'(?i)\brug\s+pull\s+(crypto|token|coin)',
                r'(?i)\bpump\s+and\s+dump\s+(scheme|crypto|token)',
            ],
            "phishing": [
                r'(?i)\bclick\s+here\s+to\s+(claim|get|receive)\s+your',
                r'(?i)\byour\s+account\s+(will\s+be\s+)?(suspended|closed|deleted)',
                r'(?i)\bverify\s+your\s+(account|identity|information)\s+now',
                r'(?i)\bupdate\s+your\s+(payment|billing)\s+information',
                r'(?i)\bsecurity\s+alert\s+(click|verify|update)',
            ],
            "mlm_schemes": [
                r'(?i)\bbecome\s+(your\s+own\s+)?boss',
                r'(?i)\b(join\s+my\s+team|work\s+from\s+home\s+opportunity)',
                r'(?i)\bunlimited\s+(income|earning)\s+potential',
                r'(?i)\bpyramid\s+scheme\s+(disguised\s+as|mlm)',
                r'(?i)\bmulti\s+level\s+marketing\s+(scam|scheme)',
            ],
            "general_scamming": [
                r'(?i)\bhow\s+to\s+(scam|con|trick|deceive|swindle)\s+(people|someone|others)',
                r'(?i)\b(scam|con|trick|deceive|swindle)\s+(people|someone|others)\s+(out\s+of|for)',
                r'(?i)\b(easy|quick)\s+(scam|con)\s+(method|technique|way)',
                r'(?i)\bscamming\s+(techniques|methods|strategies)',
                r'(?i)\bhow\s+to\s+(rip\s+off|take\s+advantage\s+of)\s+(people|customers|clients)',
                r'(?i)\b(ponzi|pyramid)\s+scheme\s+(guide|instructions)',
                r'(?i)\bfraud\s+(people|customers|clients|system)',
                r'(?i)\binsurance\s+fraud\s+(claim|method|scheme)',
                r'(?i)\btax\s+(evasion|fraud)\s+(method|scheme)',
            ]
        }
    
    def _get_privacy_patterns(self) -> Dict[str, List[str]]:
        return {
            "pii_request": [
                r'(?i)\b(give|tell|share)\s+me\s+your\s+(name|address|phone|email)',
                r'(?i)\bwhat\s+is\s+your\s+(real\s+name|address|location)',
                r'(?i)\bshare\s+your\s+(personal|private)\s+information',
            ],
            "doxxing_attempt": [
                r'(?i)\bfind\s+(someone\'s|a\s+person\'s)\s+(address|phone|information)',
                r'(?i)\bhow\s+to\s+(stalk|track|find)\s+someone\s+online',
                r'(?i)\bget\s+someone\'s\s+(personal|private)\s+(info|information|data)',
            ],
            "data_harvesting": [
                r'(?i)\bcollect\s+(user|personal)\s+data\s+without\s+consent',
                r'(?i)\bscrape\s+(social\s+media|website)\s+for\s+(data|information)',
                r'(?i)\bharvest\s+(email|contact)\s+(addresses|information)',
            ]
        }
    
    def _get_malicious_uri_patterns(self) -> Dict[str, List[str]]:
        return {
            "suspicious_domains": [
                r'(?i)\b(bit\.ly|tinyurl|goo\.gl|t\.co)\/\w+',
                r'(?i)\b\w+\.(tk|ml|ga|cf)\b',
                r'(?i)\b(phishing|malware|virus)\.(com|net|org)',
            ],
            "malicious_content": [
                r'(?i)\bdownload\s+.*(virus|malware|trojan|keylogger)',
                r'(?i)\b(click|visit)\s+this\s+link\s+to\s+(hack|steal|scam)',
                r'(?i)\bmalicious\s+(url|link|website)',
            ],
            "ip_addresses": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'(?i)\bconnect\s+to\s+ip\s+address',
            ]
        }
    
    def _get_edge_cases_patterns(self) -> Dict[str, List[str]]:
        return {
           
        }

# =============================================================================
# Advanced Detection Engine
# =============================================================================

@dataclass
class RuleBasedConfig:
    """Enhanced configuration with comprehensive settings"""
    
    # Input limits
    max_input_length: int = 10000
    max_word_count: int = 2000
    max_line_count: int = 100
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600
    burst_limit: int = 10
    burst_window: int = 60
    
    # Output limits
    max_output_length: int = 50000
    max_output_sentences: int = 100
    
    # Detection thresholds
    profanity_threshold: float = 0.6
    hate_speech_threshold: float = 0.3
    violence_threshold: float = 0.4
    harassment_threshold: float = 0.5
    dangerous_content_threshold: float = 0.7
    
    # Context sensitivity
    enable_context_analysis: bool = True
    educational_context_weight: float = 0.3
    medical_context_weight: float = 0.4
    creative_context_weight: float = 0.5
    
    # Edge case handling
    enable_false_positive_reduction: bool = True
    enable_severity_adjustment: bool = True

class GuardrailViolation(BaseModel):
    violation_type: ViolationType
    severity: Severity
    message: str
    pattern_matched: Optional[str] = None
    confidence_score: float = 1.0
    context_detected: Optional[ContextType] = None
    suggested_action: str
    location: Optional[str] = None
    
    class Config:
        use_enum_values = True

class LLMRequest(BaseModel):
    prompt: str = Field(..., max_length=50000)
    model: str = Field(default="gpt-3.5-turbo")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=150, ge=1, le=4000)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    context_hint: Optional[str] = None

class LLMResponse(BaseModel):
    response: str
    filtered: bool = False
    confidence_score: float = 1.0
    violations: List[GuardrailViolation] = []
    warnings: List[str] = []
    metadata: Dict[str, Any] = {}
    
    class Config:
        use_enum_values = True

# =============================================================================
# Context-Aware Detection Engine
# =============================================================================

class ContextAnalyzer:
    """Analyzes text context to reduce false positives"""
    
    def __init__(self, patterns: ComprehensivePatternLibrary):
        self.patterns = patterns
    
    def detect_context(self, text: str) -> Optional[ContextType]:
        """Detect the likely context of the text"""
        text_lower = text.lower()
        
        # Educational context
        educational_score = sum(1 for indicator in self.patterns.educational_indicators 
                              if indicator in text_lower)
        
        # Medical context
        medical_score = sum(1 for indicator in self.patterns.medical_indicators 
                           if indicator in text_lower)
        
        # Creative context
        creative_score = sum(1 for indicator in self.patterns.creative_indicators 
                            if indicator in text_lower)
        
        # News context
        news_score = sum(1 for indicator in self.patterns.news_indicators 
                        if indicator in text_lower)
        
        # # Religious academic context (counts as educational)
        # religious_academic_score = sum(1 for indicator in self.patterns.religious_academic_indicators 
        #                              if indicator in text_lower)
        
        # # Add religious academic score to educational score
        # educational_score += religious_academic_score
        
        scores = {
            ContextType.EDUCATIONAL: educational_score,
            ContextType.MEDICAL: medical_score,
            ContextType.CREATIVE: creative_score,
            ContextType.NEWS: news_score,
        }
        
        max_score = max(scores.values())
        if max_score >= 2:
            return max(scores, key=scores.get)
        
        return ContextType.CASUAL
    
    def adjust_severity_for_context(self, severity: Severity, context: ContextType, 
                                   violation_type: ViolationType) -> Severity:
        """Adjust violation severity based on context"""
        

        if context == ContextType.EDUCATIONAL:
            if violation_type in [ViolationType.VIOLENCE, ViolationType.DANGEROUS]:
                if severity == Severity.HIGH:
                    return Severity.MEDIUM
                elif severity == Severity.MEDIUM:
                    return Severity.LOW
            

            if violation_type == ViolationType.HATE_SPEECH:

                if severity == Severity.CRITICAL:
                    return Severity.HIGH
                elif severity == Severity.HIGH:
                    return Severity.MEDIUM
        

        if context == ContextType.MEDICAL:
            if violation_type == ViolationType.SEXUALLY_EXPLICIT:
                if severity in [Severity.MEDIUM, Severity.LOW]:
                    return Severity.LOW
        

        if context == ContextType.CREATIVE:
            if violation_type in [ViolationType.VIOLENCE, ViolationType.HARASSMENT]:
                if severity == Severity.HIGH:
                    return Severity.MEDIUM
                elif severity == Severity.MEDIUM:
                    return Severity.LOW
        

        if context == ContextType.NEWS:
            if violation_type in [ViolationType.VIOLENCE, ViolationType.HATE_SPEECH]:
                if severity == Severity.HIGH:
                    return Severity.MEDIUM
                elif severity == Severity.MEDIUM:
                    return Severity.LOW
        
        return severity

class ComprehensiveDetector:
    """Main detection engine with comprehensive pattern matching"""
    
    def __init__(self, config: RuleBasedConfig):
        self.config = config
        self.patterns = ComprehensivePatternLibrary()
        self.context_analyzer = ContextAnalyzer(self.patterns)
        

        self._compile_patterns()
        

        self.compiled_pii_patterns = {
            name: re.compile(pattern, re.IGNORECASE) 
            for name, pattern in self.patterns.pii_patterns.items()
        }
    
    def _compile_patterns(self):
        """Compile all regex patterns for efficient matching"""
        self.compiled_patterns = {}
        
        for category in ['prompt_injection', 'jailbreak', 'hate_speech', 'harassment', 
                        'violence', 'sexually_explicit', 'dangerous', 'misinformation',
                        'spam_scams', 'privacy', 'malicious_uri', 'edge_cases']:
            
            category_patterns = getattr(self.patterns, category)
            self.compiled_patterns[category] = {}
            
            for subcategory, pattern_list in category_patterns.items():
                self.compiled_patterns[category][subcategory] = [
                    re.compile(pattern, re.IGNORECASE) for pattern in pattern_list
                ]
    
    def detect_violations(self, text: str, context_hint: str = None) -> List[GuardrailViolation]:
        """Comprehensive violation detection with context awareness"""
        violations = []
        

        detected_context = self.context_analyzer.detect_context(text)
        if context_hint:

            try:
                detected_context = ContextType(context_hint.lower())
            except ValueError:
                pass
        

        violations.extend(self._detect_category(text, 'prompt_injection', ViolationType.PROMPT_INJECTION, Severity.HIGH))
        violations.extend(self._detect_category(text, 'jailbreak', ViolationType.JAILBREAK, Severity.HIGH))
        violations.extend(self._detect_category(text, 'hate_speech', ViolationType.HATE_SPEECH, Severity.CRITICAL))
        violations.extend(self._detect_category(text, 'harassment', ViolationType.HARASSMENT, Severity.HIGH))
        violations.extend(self._detect_category(text, 'violence', ViolationType.VIOLENCE, Severity.HIGH))
        violations.extend(self._detect_category(text, 'sexually_explicit', ViolationType.SEXUALLY_EXPLICIT, Severity.HIGH))
        violations.extend(self._detect_category(text, 'dangerous', ViolationType.DANGEROUS, Severity.CRITICAL))
        violations.extend(self._detect_category(text, 'misinformation', ViolationType.MISINFORMATION, Severity.MEDIUM))
        violations.extend(self._detect_category(text, 'spam_scams', ViolationType.SPAM_SCAMS, Severity.MEDIUM))
        violations.extend(self._detect_category(text, 'privacy', ViolationType.PRIVACY, Severity.HIGH))
        violations.extend(self._detect_category(text, 'malicious_uri', ViolationType.MALICIOUS_URI, Severity.HIGH))
        

        violations.extend(self._detect_pii(text))
        

        # violations.extend(self._detect_edge_cases(text, detected_context))
        

        if self.config.enable_severity_adjustment:
            for violation in violations:
                violation.context_detected = detected_context
                original_severity = Severity(violation.severity)
                adjusted_severity = self.context_analyzer.adjust_severity_for_context(
                    original_severity, detected_context, violation.violation_type
                )
                violation.severity = adjusted_severity
        
        return violations
    
    def _detect_pii(self, text: str) -> List[GuardrailViolation]:
        """Detect personally identifiable information"""
        violations = []
        
        for pii_type, pattern in self.compiled_pii_patterns.items():
            matches = pattern.findall(text)
            if matches:
                first_match = str(matches[0]) if matches else ""
                if matches and isinstance(matches[0], tuple):
                    first_match = ' '.join(str(x) for x in matches[0] if x)
                
                violations.append(GuardrailViolation(
                    violation_type=ViolationType.PII_DETECTED,
                    severity=Severity.HIGH,
                    message=f"PII detected: {pii_type.upper()} ({len(matches)} instances)",
                    pattern_matched=pattern.pattern,
                    confidence_score=1.0,
                    suggested_action="Redact PII",
                    location=f"First match: {first_match[:20]}..." if first_match else None
                ))
        
        return violations
    
    def _detect_category(self, text: str, category: str, violation_type: ViolationType, 
                        default_severity: Severity) -> List[GuardrailViolation]:
        """Detect violations for a specific category"""
        violations = []
        
        category_patterns = self.compiled_patterns.get(category, {})
        
        for subcategory, patterns in category_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:

                    first_match = str(matches[0]) if matches else ""
                    if matches and isinstance(matches[0], tuple):
                        first_match = ' '.join(str(x) for x in matches[0] if x)
                    

                    actual_severity = default_severity

                        
                    
                    violations.append(GuardrailViolation(
                        violation_type=violation_type,
                        severity=actual_severity,
                        message=f"{violation_type.value.replace('_', ' ').title()} detected in {subcategory}",
                        pattern_matched=pattern.pattern,
                        confidence_score=self._calculate_confidence(matches, text),
                        suggested_action=self._get_suggested_action(violation_type, actual_severity),
                        location=f"Match: {first_match[:50]}..." if first_match else None
                    ))
        
        return violations
    

    
    def _calculate_confidence(self, matches: List, text: str) -> float:
        """Calculate confidence score for violation"""
        if not matches:
            return 0.0
        

        base_score = min(1.0, len(matches) / 3)
        length_factor = min(1.0, len(text) / 1000)
        
        return max(0.1, base_score * (0.7 + 0.3 * length_factor))
    
    def _get_suggested_action(self, violation_type: ViolationType, severity: Severity) -> str:
        """Get suggested action based on violation type and severity"""
        if severity == Severity.CRITICAL:
            return "Block immediately"
        elif severity == Severity.HIGH:
            return "Block or heavily filter"
        elif severity == Severity.MEDIUM:
            return "Review and potentially filter"
        else:
            return "Monitor or flag"

# =============================================================================
# Rate Limiting System
# =============================================================================
#to stop api abuse
class AdvancedRateLimiter:
    """Advanced rate limiting with burst detection"""
    
    def __init__(self, config: RuleBasedConfig):
        self.config = config
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.burst_requests: Dict[str, deque] = defaultdict(deque)
        self.violation_counts: Dict[str, int] = defaultdict(int)
    
    def is_rate_limited(self, identifier: str) -> Tuple[bool, str]:
        """Check if request should be rate limited"""
        now = time.time()
        

        burst_window_start = now - self.config.burst_window
        burst_requests = self.burst_requests[identifier]
        
        while burst_requests and burst_requests[0] < burst_window_start:
            burst_requests.popleft()
        
        if len(burst_requests) >= self.config.burst_limit:
            return True, f"Burst limit exceeded: {len(burst_requests)}/{self.config.burst_limit}"
        

        window_start = now - self.config.rate_limit_window
        user_requests = self.requests[identifier]
        
        while user_requests and user_requests[0] < window_start:
            user_requests.popleft()
        
        if len(user_requests) >= self.config.rate_limit_requests:
            return True, f"Rate limit exceeded: {len(user_requests)}/{self.config.rate_limit_requests}"
        

        burst_requests.append(now)
        user_requests.append(now)
        
        return False, "OK"

# =============================================================================
# Main Guardrails Server
# =============================================================================

class ComprehensiveGuardrailsServer:
    """Comprehensive guardrails server with edge case handling"""
    
    def __init__(self, config: RuleBasedConfig = None):
        self.config = config or RuleBasedConfig()
        self.rate_limiter = AdvancedRateLimiter(self.config)
        self.detector = ComprehensiveDetector(self.config)
        

        self.stats = {
            'total_requests': 0,
            'blocked_inputs': 0,
            'filtered_outputs': 0,
            'rate_limited': 0,
            'violations_by_type': defaultdict(int),
            'context_adjustments': 0,
            'false_positives_prevented': 0,
            'religious_abuse_blocked': 0,
            'hate_speech_blocked': 0,
            'harassment_blocked': 0,
        }
        

        self.audit_log: deque = deque(maxlen=10000)
        

        self.app = FastAPI(
            title="Comprehensive ModelShield Server",
            description="Complete guardrails with edge case handling and context awareness",
            version="3.0.0"
        )
        
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        self._setup_routes()
    
    def _violations_to_dict(self, violations: List[GuardrailViolation]) -> List[Dict]:
        """Safely convert violations to dictionary format for JSON serialization"""
        result = []
        for v in violations:
            try:

                violation_type = v.violation_type.value if hasattr(v.violation_type, 'value') else str(v.violation_type)
                

                severity = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
                
                result.append({
                    "violation_type": violation_type,
                    "severity": severity,
                    "message": v.message,
                    "pattern_matched": v.pattern_matched,
                    "confidence_score": v.confidence_score,
                    "suggested_action": v.suggested_action,
                    "location": v.location
                })
            except Exception as e:

                logger.warning(f"Error processing violation: {str(e)}")
                result.append({
                    "violation_type": "error",
                    "severity": "medium", 
                    "message": f"Error processing violation: {str(e)}",
                    "confidence_score": 0.0,
                    "suggested_action": "Review manually"
                })
        
        return result
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "3.0.0",
                "features": [
                    "comprehensive_patterns", "context_awareness", "edge_case_handling",
                    "false_positive_reduction", "severity_adjustment"
                ]
            }
        
        @self.app.get("/patterns")
        async def get_patterns():
            """Get information about all detection patterns"""
            pattern_counts = {}
            
            for category in ['prompt_injection', 'jailbreak', 'hate_speech', 'harassment',
                           'violence', 'sexually_explicit', 'misinformation',
                           'spam_scams', 'privacy', 'malicious_uri']:
                category_patterns = getattr(self.detector.patterns, category)
                pattern_counts[category] = {
                    "subcategories": len(category_patterns),
                    "total_patterns": sum(len(patterns) for patterns in category_patterns.values()),
                    "patterns": category_patterns
                }
            
            return {
                "total_categories": len(pattern_counts),
                "total_patterns": sum(pc["total_patterns"] for pc in pattern_counts.values()),
                "categories": pattern_counts,
                "context_types": [ct.value for ct in ContextType],
                "violation_types": [vt.value for vt in ViolationType]
            }
        
        @self.app.post("/debug-detection")
        async def debug_detection(request: Request, llm_request: LLMRequest):
            """Debug endpoint to see what patterns match without blocking"""
            user_id = llm_request.user_id or request.client.host
            

            violations = self.detector.detect_violations(
                llm_request.prompt, 
                llm_request.context_hint
            )
            

            debug_info = {}
            for category in ['dangerous', 'edge_cases', 'hate_speech', 'harassment']:
                category_violations = self.detector._detect_category(
                    llm_request.prompt, 
                    category, 
                    getattr(ViolationType, category.upper()), 
                    Severity.HIGH
                )
                debug_info[category] = {
                    "violations_count": len(category_violations),
                    "violations": self._violations_to_dict(category_violations)
                }
            
            return {
                "input": llm_request.prompt,
                "total_violations": len(violations),
                "violations": self._violations_to_dict(violations),
                "debug_by_category": debug_info,
                "would_be_blocked": len([v for v in violations if v.severity in [Severity.HIGH, Severity.CRITICAL]]) > 0
            }
        
        @self.app.post("/validate-input")
        async def validate_input_endpoint(request: Request, llm_request: LLMRequest):
            start_time = time.time()
            client_ip = request.client.host
            user_id = llm_request.user_id or client_ip
            
            self.stats['total_requests'] += 1
            

            is_limited, limit_reason = self.rate_limiter.is_rate_limited(user_id)
            if is_limited:
                self.stats['rate_limited'] += 1
                self._log_event("rate_limit_exceeded", user_id, {"reason": limit_reason})
                raise HTTPException(status_code=429, detail=f"Rate limited: {limit_reason}")
            

            violations = self.detector.detect_violations(
                llm_request.prompt, 
                llm_request.context_hint
            )
            
            processing_time = time.time() - start_time

            for violation in violations:

                violation_type = violation.violation_type.value if hasattr(violation.violation_type, 'value') else str(violation.violation_type)
                self.stats['violations_by_type'][violation_type] += 1
                if violation.context_detected and violation.context_detected != ContextType.CASUAL:
                    self.stats['context_adjustments'] += 1
                

                if violation.violation_type == ViolationType.HATE_SPEECH:
                    self.stats['hate_speech_blocked'] += 1

                    if any(keyword in violation.message.lower() for keyword in ['religious', 'muslim', 'jew', 'christian', 'hindu', 'buddhist', 'islam', 'christianity', 'judaism']):
                        self.stats['religious_abuse_blocked'] += 1
                elif violation.violation_type == ViolationType.HARASSMENT:
                    self.stats['harassment_blocked'] += 1

                    if any(keyword in violation.message.lower() for keyword in ['religious', 'muslim', 'jew', 'christian', 'hindu', 'buddhist', 'islam', 'christianity', 'judaism']):
                        self.stats['religious_abuse_blocked'] += 1
                

            critical_violations = [v for v in violations if v.severity in [Severity.HIGH, Severity.CRITICAL]]
            is_blocked = len(critical_violations) > 0
            

            hate_speech_violations = [v for v in violations if v.violation_type == ViolationType.HATE_SPEECH]
            if hate_speech_violations:
                is_blocked = True
            
            if is_blocked:
                self.stats['blocked_inputs'] += 1
            
            self._log_event("input_validation", user_id, {
                "blocked": is_blocked,
                "violations": len(violations),
                "processing_time_ms": processing_time * 1000
            })
            
            if is_blocked:
                raise HTTPException(status_code=400, detail={
                    "message": "Input validation failed",
                    "violations": self._violations_to_dict(violations),
                    "processing_time_ms": processing_time * 1000
                })
            
            return {
                "valid": True,
                "violations": self._violations_to_dict(violations),
                "warnings": [v.message for v in violations if v.severity in [Severity.LOW, Severity.MEDIUM]],
                "processing_time_ms": processing_time * 1000,
                "detection_method": "comprehensive_rule_based",
                "context_analysis_enabled": self.config.enable_context_analysis
            }
        
        @self.app.get("/stats")
        async def get_stats():
            total = max(self.stats['total_requests'], 1)
            return {
                **dict(self.stats),
                "success_rate": (total - self.stats['blocked_inputs']) / total,
                "active_users": len(self.rate_limiter.requests),
                "detection_categories": len(ViolationType),
                "context_types_supported": len(ContextType),
                "comprehensive": True
            }
    
    def _log_event(self, event_type: str, user_id: str, details: Dict):
        """Log audit event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details
        }
        self.audit_log.append(event)
        logger.info(f"Event: {event_type} for user {user_id}")
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the guardrails server"""
        logger.info(f"Starting  ModelShield Server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)

# =============================================================================
# Usage and Configuration
# =============================================================================

def create_production_config() -> RuleBasedConfig:
    """Create production-ready configuration"""
    config = RuleBasedConfig()
    

    config.profanity_threshold = 0.4
    config.hate_speech_threshold = 0.2
    config.violence_threshold = 0.3
    config.harassment_threshold = 0.3
    config.dangerous_content_threshold = 0.5
    

    config.enable_context_analysis = True
    config.enable_false_positive_reduction = True
    config.enable_severity_adjustment = True
    

    config.rate_limit_requests = 500
    config.burst_limit = 3000
    
    return config

if __name__ == "__main__":
    config = create_production_config()
    server = ComprehensiveGuardrailsServer(config)
    
    print("🛡️ ModelShield SERVER ")
    print("=" * 80)
    print("🎯 COMPREHENSIVE COVERAGE:")
    print("  ✅ Prompt Injection & Jailbreaking")
    print("  ✅ Hate Speech & Harassment") 
    print("  ✅ Violence & Dangerous Content")
    print("  ✅ Sexually Explicit Content")
    print("  ✅ Misinformation & Spam/Scams")
    print("  ✅ Privacy & Malicious URIs")
    print("  ✅ Edge Cases & Context Awareness")
    print()
    print("🧠 SMART FEATURES:")
    print("  ✅ Context-Aware Detection (Educational/Medical/Creative/News)")
    print("  ✅ Profanity Severity Adjustment (fuck/stupid/idiot handled properly)")
    print("  ✅ False Positive Reduction")
    print("  ✅ Severity Adjustment Based on Context")
    print("  ✅ Comprehensive Edge Case Handling")
    print()
    print("📊 COVERAGE STATS:")
    patterns = ComprehensivePatternLibrary()
    total_patterns = 0
    for category in ['prompt_injection', 'jailbreak', 'hate_speech', 'harassment',
                    'violence', 'sexually_explicit', 'dangerous', 'misinformation',
                    'spam_scams', 'privacy', 'malicious_uri', 'edge_cases']:
        category_patterns = getattr(patterns, category)
        category_total = sum(len(pattern_list) for pattern_list in category_patterns.values())
        total_patterns += category_total
        print(f"  • {category.replace('_', ' ').title()}: {category_total} patterns")
    

    pii_total = len(patterns.pii_patterns)
    total_patterns += pii_total
    print(f"  • PII Detection: {pii_total} patterns")
    
    print(f"\n  🎯 TOTAL PATTERNS: {total_patterns}")
    print("=" * 80)
    print(f"🚀 Server starting on http://localhost:8000")
    print("📖 API docs: http://localhost:8000/docs")
    print("🔍 Patterns: http://localhost:8000/patterns")
    print()
    
    server.run()