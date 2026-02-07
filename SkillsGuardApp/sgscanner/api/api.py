from fastapi import FastAPI
from .router import router as api_router
app = FastAPI(title='Skill Scanner API', description='Security scanning API for agent skills packages', version='0.2.0', docs_url='/docs', redoc_url='/redoc')
app.include_router(api_router)
