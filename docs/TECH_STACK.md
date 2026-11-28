# Technology Stack

## MVP choices
- **Language:** Python
- **Backend:** FastAPI
- **Validation:** Pydantic
- **Policy configuration:** YAML and/or JSON
- **SDK:** Python decorator/wrapper around custom tools
- **Audit storage:** JSONL initially or SQLite; select one primary implementation and document the choice
- **Frontend:** React or a minimal HTML dashboard. Prefer React only if time permits without jeopardizing backend correctness.
- **Testing:** pytest; FastAPI TestClient or HTTPX as appropriate

## Engineering guidance
- Use type hints.
- Keep policy evaluation independent from HTTP routes.
- Keep the SDK usable without requiring the dashboard.
- Pin dependencies in a requirements file or lockfile.
- Avoid adding heavyweight agent frameworks to the MVP.
- Do not claim LangChain, CrewAI, or AutoGen support until a tested, version-pinned adapter exists.
