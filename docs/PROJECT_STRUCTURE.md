# Recommended Project Structure

```text
agentshield/
├── README.md
├── AI_AGENT_INSTRUCTIONS.md
├── PROJECT_OVERVIEW.md
├── SYSTEM_ARCHITECTURE.md
├── TECH_STACK.md
├── PROJECT_STRUCTURE.md
├── BACKEND_SPECIFICATION.md
├── SECURITY_ENGINE.md
├── POLICY_ENGINE.md
├── SDK_SPECIFICATION.md
├── AUDIT_LOGGING.md
├── FRONTEND_SPECIFICATION.md
├── API_DOCUMENTATION.md
├── TESTING_STRATEGY.md
├── IMPLEMENTATION_ROADMAP.md
├── VSCODE_CODING_PROMPTS.md
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── models/
│   │   ├── core/
│   │   ├── services/
│   │   └── storage/
│   ├── policies/
│   │   └── default_policy.yaml
│   ├── tests/
│   └── requirements.txt
├── sdk/
│   ├── agentshield/
│   └── tests/
├── frontend/
│   └── (React app or minimal dashboard)
├── examples/
│   ├── demo_agent.py
│   └── sample_vendor_document.txt
├── scenarios/
│   └── scenarios.yaml
└── data/
    └── .gitkeep
```

The coding agent may adjust this structure if it explains why and updates this document. Do not create duplicate implementations of the same policy logic in the API and SDK.
