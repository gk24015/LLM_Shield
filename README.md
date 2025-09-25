
# ShieldX  

**ShieldX** is a production-ready framework for implementing **safety guardrails** in Large Language Model (LLM) applications. It provides **multi-layered protection** against prompt injection, PII leaks, unsafe content, and ensures **responsible AI deployment** across industries.  

---

🌟 **Core Capabilities**  

### Multi-Tiered Detection  
- 📝 **Rule-Based Filters:** Regex-driven checks for known attack patterns  
- 🔍 **Advanced PII Protection:** Microsoft Presidio integration for personal data recognition  
- 🧠 **Semantic Defense:** Transformer-based models to catch obfuscation and novel threats  
- 📤 **Response Screening:** On-the-fly validation of model outputs before delivery  

### Built for Production  
- ⚡ **FastAPI Backend:** High-performance async API with auto docs  
- 🔄 **Adaptive Risk Handling:** Severity tuned per context (education, healthcare, creative, news)  
- 📊 **Deep Observability:** Built-in monitoring, analytics, and violation logging  
- 🎯 **Broad Coverage:** 500+ rules across 12+ categories of unsafe behaviors  
- ⚙️ **Optimized by Default:** `en_core_web_sm` and transformer library are **disabled internally unless explicitly required**, reducing latency and resource load.  

### Developer-Centric  
- 🔧 **Plug-and-Play Integration:** Python SDK + REST endpoints  
- 📋 **Evaluation Suite:** Built-in benchmarking and testing tools  
- 🎨 **Customizable Framework:** Extendable rules and configurable thresholds  
- 📖 **Comprehensive Documentation:** Interactive examples and usage guides  

---

🚀 **Getting Started**  

### Installation  
```bash
# Clone repository
git clone <your-repo-url>
cd shieldx

# Install dependencies
pip install -r requirements.txt

# (Optional) Download spaCy model for advanced PII detection
python -m spacy download en_core_web_sm

# Start the service
python startup.py
```  

### Basic Usage  
```python
from guardrails import ProductionGuardrailsServer, ProductionConfig

# Configure shield
config = ProductionConfig(
    enable_semantic_detection=True,
    enable_enhanced_pii=True,
    enable_output_scanning=True
)

# Launch service
server = ProductionGuardrailsServer(config)
server.run(host="0.0.0.0", port=8000)
```  

### API Endpoints  
```bash
# Validate input prompt
curl -X POST "http://localhost:8000/validate-input"      -H "Content-Type: application/json"      -d '{"prompt": "Hello, how can I assist you today?", "user_id": "user123"}'

# Validate model response
curl -X POST "http://localhost:8000/validate-output"      -H "Content-Type: application/json"      -d '{"response_text": "Here’s some useful information...", "original_prompt": "How do I...?"}'
```  

---

🏗️ **How ShieldX Works**  

```mermaid
flowchart LR
    A[User Input] --> B[Rule Matching<br/>(Regex Patterns)]
    B --> C[PII Check<br/>(Presidio NLP)]
    C --> D[Semantic Analysis<br/>(Transformer Models)]
    D --> E[Context Awareness<br/>(Contextual Layer)]
    E --> F[Final Decision<br/>(Allow / Block / Filter)]

    %% Notes
    B --- Bnote["• Prompt Hacks<br/>• Hate Speech<br/>• Violence"]
    C --- Cnote["• Emails/SSN<br/>• Payment IDs<br/>• API Keys"]
    D --- Dnote["• Toxic/Unsafe<br/>• Obfuscation<br/>• Similarity"]
    E --- Enote["• Education?<br/>• Medical?<br/>• Creative?<br/>• News?"]
```

---

📊 **Detection Coverage**  

| Category           | Scope            | Examples                                    |  
|--------------------|-----------------|--------------------------------------------|  
| **Prompt Injection** | 25+ rules       | Jailbreak attempts, system override prompts |  
| **PII Protection**   | 15+ identifiers | Emails, SSNs, payment cards, API tokens     |  
| **Content Safety**   | 200+ patterns   | Inappropriate, harmful, or unsafe content   |  
| **Context Handling** | 4 scenarios     | Educational, medical, creative, news        |  
| **Output Guarding**  | 10+ checks      | Data leakage prevention, filtered responses |  

---

🔗 **Integration with RAG Pipelines**  

ShieldX strengthens **Retrieval-Augmented Generation (RAG)** workflows at **three levels**:  

1. **Pre-Indexing (Data Ingestion):**  
   - Clean incoming documents to **remove PII and unsafe content** before storing in vector DBs.  

2. **Query Time (User Input):**  
   - Validate user queries to **block injections and malicious searches**.  

3. **Response Time (LLM Output):**  
   - Filter model responses before delivery to **prevent data leakage or unsafe outputs**.  

---

### ⚙️ Example: ShieldX in a RAG Workflow  

```python
from guardrails import ProductionGuardrailsServer, ProductionConfig
from some_vector_db import VectorDB
from some_llm import LLMClient

# 1. Initialize ShieldX
config = ProductionConfig(
    enable_semantic_detection=True,
    enable_enhanced_pii=True,
    enable_output_scanning=True
)
shieldx = ProductionGuardrailsServer(config)

# 2. Connect to your vector database and LLM
db = VectorDB("my-knowledge-base")
llm = LLMClient(api_key="your-api-key")

# ---- PIPELINE ----
def rag_pipeline(user_query: str, user_id: str):

    # Step A: Validate input
    input_result = shieldx.validate_input(
        {"prompt": user_query, "user_id": user_id}
    )
    if not input_result["allowed"]:
        return {"error": "Query rejected by ShieldX", "details": input_result}

    # Step B: Retrieve documents
    retrieved_docs = db.search(user_query, top_k=5)

    # Step C: Build augmented prompt
    context = "\n".join([doc["content"] for doc in retrieved_docs])
    augmented_prompt = f"Answer using context:\n{context}\n\nQuestion: {user_query}"

    # Step D: Get LLM response
    raw_response = llm.generate(augmented_prompt)

    # Step E: Validate output
    output_result = shieldx.validate_output(
        {"response_text": raw_response, "original_prompt": user_query}
    )
    if not output_result["allowed"]:
        return {"error": "Response blocked by ShieldX", "details": output_result}

    return {"answer": raw_response}
```

---

### 📌 Best Practices  

- ✅ **Pre-Index Cleaning:** Run ShieldX on datasets before indexing into vector DBs.  
- ✅ **Query Firewall:** Place ShieldX at the entry point to catch unsafe prompts.  
- ✅ **Response Validation:** Scan all model outputs before sending them to users.  
- ⚡ **Performance Tip:** If semantic detection isn’t needed at every step, disable transformers for **lower latency**.  

---
