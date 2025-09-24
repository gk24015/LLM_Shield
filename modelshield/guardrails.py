from .config import ProductionConfig
from fastapi import FastAPI
from loguru import logger

class ProductionGuardrailsServer:
    def __init__(self, config: ProductionConfig):
        self.config = config
        self.app = FastAPI(title="ModelShield Guardrails API", description="LLM Safety Guardrails", version="1.0.0")
        self._setup_routes()
        logger.info("Guardrails server initialized with config: {}", config)

    def _setup_routes(self):
        from .routes import add_routes
        add_routes(self.app, self.config)

    def run(self, host: str = "0.0.0.0", port: int = 8000):
        import uvicorn
        logger.info(f"Starting server at http://{host}:{port}")
        uvicorn.run(self.app, host=host, port=port)
