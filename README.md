# 🛡️ CodeSentinel AI

**AI-powered secure code review system** using **Agentic AI (LangGraph)** and **Spring Boot**.

CodeSentinel AI integrates with GitHub Pull Requests and automatically reviews code for security vulnerabilities using:
1. **Static code analysis** (rule-based regex engine)
2. **Agentic AI workflow** (LangGraph multi-agent pipeline)
3. **Retrieval-Augmented Generation (RAG)** using OWASP Top 10 guidelines

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────────────────────┐     ┌─────────────────────────────────┐
│   GitHub PR      │────▶│  Spring Boot Backend [:8080]     │────▶│  Python AI Engine [:8000]       │
│   Webhook        │     │                                  │     │                                 │
│                  │     │  • Webhook Controller             │     │  • FastAPI Gateway               │
│                  │     │  • Static Analysis Engine          │     │  • LangGraph Orchestrator         │
│                  │     │  • Review Aggregator               │     │  • 5 AI Agents                    │
│                  │     │  • H2 Database                     │     │  • FAISS RAG Pipeline             │
└─────────────────┘     └──────────────────────────────────┘     └─────────────────────────────────┘
                                        │
                               ┌────────┴────────┐
                               │  Demo Dashboard  │
                               │  frontend/       │
                               └─────────────────┘
```

### AI Agent Pipeline (LangGraph)

```
START → RAG Enrichment → Code Analyzer → Security Agent → Fix Generator → Explanation Agent → Reviewer → END
```

---

## 🚀 Quick Start

### Prerequisites
- **Java 17+** (tested with Java 23)
- **Python 3.10+**
- **Maven** (or use the downloaded Maven in `/tmp/apache-maven-3.9.6/`)

### 1. Start the Spring Boot Backend

```bash
cd backend-spring
/tmp/apache-maven-3.9.6/bin/mvn spring-boot:run
```

The backend starts on `http://localhost:8080`.

### 2. Start the Python AI Engine

```bash
cd ai-engine

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# (Optional) Set OpenAI API key for real LLM analysis
export OPENAI_API_KEY=your-key-here

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The AI engine starts on `http://localhost:8000`.

### 3. Open the Dashboard

Open `frontend/index.html` in your browser and click **"Run Security Review"**.

### 4. (Alternative) Use Docker Compose

```bash
docker-compose up --build
```

---

## 📡 API Endpoints

### Spring Boot Backend (`:8080`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/webhook` | Receive GitHub PR webhook |
| `GET` | `/api/webhook/health` | Health check |
| `GET` | `/api/reviews` | List all reviews |
| `GET` | `/api/reviews/{id}` | Get review details + vulnerabilities |
| `POST` | `/api/reviews/trigger` | Manually trigger a review (demo) |

### Python AI Engine (`:8000`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze code diffs via LangGraph |
| `GET` | `/api/health` | Health check |

---

## 🧪 Testing

### Spring Boot Tests
```bash
cd backend-spring
/tmp/apache-maven-3.9.6/bin/mvn test
# 19 tests, all passing ✅
```

### Python Tests
```bash
cd ai-engine
pytest tests/ -v
```

---

## 🔍 Vulnerability Detection

### Static Analysis Rules (10 rules)
| Rule | Severity | OWASP |
|------|----------|-------|
| SQL Injection | HIGH | A03:2021 |
| Cross-Site Scripting (XSS) | HIGH | A03:2021 |
| Hardcoded Secret | CRITICAL | A02:2021 |
| Hardcoded Connection String | HIGH | A02:2021 |
| Command Injection | CRITICAL | A03:2021 |
| Insecure Deserialization | HIGH | A08:2021 |
| Path Traversal | HIGH | A01:2021 |
| Insecure Cookie | MEDIUM | A05:2021 |
| Weak Cryptography | MEDIUM | A02:2021 |
| Mass Assignment | MEDIUM | A01:2021 |

### AI Agents
- **Code Analyzer** — Identifies potential vulnerable patterns
- **Security Agent** — Maps to OWASP Top 10 with RAG context
- **Fix Generator** — Generates actionable fix suggestions
- **Explanation Agent** — Creates developer-friendly explanations
- **Final Reviewer** — Consolidates, deduplicates, and prioritizes

---

## 📁 Project Structure

```
CodeSentinel AI/
├── backend-spring/          # Java Spring Boot backend
│   ├── src/main/java/com/codesentinel/
│   │   ├── controller/      # REST controllers
│   │   ├── service/         # Business logic (7 services)
│   │   ├── model/           # JPA entities + enums
│   │   ├── dto/             # Data transfer objects
│   │   ├── repository/      # JPA repositories
│   │   └── config/          # Configuration classes
│   └── src/test/            # Unit tests
│
├── ai-engine/               # Python AI engine
│   ├── app/
│   │   ├── agents/          # 5 LangGraph agents
│   │   ├── workflows/       # LangGraph graph definition
│   │   ├── rag/             # FAISS vector store + OWASP loader
│   │   ├── llm/             # LLM client (OpenAI + mock)
│   │   └── models/          # State + Pydantic schemas
│   ├── data/owasp/          # OWASP Top 10 knowledge base (10 docs)
│   └── tests/               # Python tests
│
├── frontend/                # Demo dashboard UI
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── docker-compose.yml       # Multi-service orchestration
└── README.md
```

---

## 🔮 Extensibility

- **Add new agents**: Create a new file in `ai-engine/app/agents/`, implement the node function, and add it to the graph in `security_review.py`
- **Add detection rules**: Add new `SecurityRule` entries in `StaticAnalysisService.java`
- **Swap LLM provider**: Modify `ai-engine/app/llm/client.py` to use any LangChain-compatible LLM
- **Real GitHub integration**: Replace `GitHubApiService.java` mock with real GitHub REST API calls
- **Production database**: Switch from H2 to PostgreSQL by updating `application.yml` and `docker-compose.yml`

---

## 📄 Sample Output

```json
{
    "file": "UserService.java",
    "vulnerability": "SQL Injection",
    "severity": "HIGH",
    "issue": "User input directly concatenated into SQL query string",
    "fix": "Use PreparedStatement or parameterized queries",
    "explanation": "SQL injection allows attackers to manipulate database queries...",
    "owasp": "A03:2021 Injection"
}
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Java Spring Boot 3.2, JPA, H2 |
| AI Engine | Python, FastAPI, LangGraph, LangChain |
| RAG | FAISS, Sentence Transformers |
| LLM | OpenAI GPT-4o-mini (with mock fallback) |
| Frontend | HTML/CSS/JS (vanilla) |
| DevOps | Docker, Docker Compose |

---

*Built with ❤️ by CodeSentinel AI*
