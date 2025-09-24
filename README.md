# ModelShield

ModelShield is a comprehensive, production-ready framework for implementing safety guardrails in Large Language Model (LLM) applications. It provides multi-layered protection against prompt injection, content policy violations, and ensures responsible AI deployment.

## Features
- Multi-layered detection: regex, PII (Presidio), semantic (transformers)
- Output scanning and real-time validation
- FastAPI server with automatic Swagger docs
- Context-aware severity and analytics
- Modular, extensible architecture

## Quick Start
```bash
pip install -r requirements.txt
uvicorn modelshield.main:app --reload
```

## Example Usage
```python
from guardrails import ProductionGuardrailsServer, ProductionConfig
config = ProductionConfig(
    enable_semantic_detection=True,
    enable_enhanced_pii=True,
    enable_output_scanning=True
)
server = ProductionGuardrailsServer(config)
server.run(host="0.0.0.0", port=8000)
```

## API Endpoints
- `/validate-input` : Validate user input
- `/validate-output` : Validate model output

See the Swagger docs at `/docs` after starting the server.

## Architecture
Input → Pattern Detection → PII Detection → Semantic Analysis → Context Analysis → Decision
