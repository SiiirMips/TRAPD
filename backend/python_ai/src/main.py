# backend/python_ai/src/main.py
from fastapi import FastAPI
import uvicorn
import os
from dotenv import load_dotenv

# Importiere deine Router
from api.routes.honeypot_routes import router as honeypot_router
from api.routes.usb_drop_routes import router as usb_drop_router

# Lade Umgebungsvariablen
load_dotenv()

app = FastAPI(
    title="YourProjectName AI Backend API",
    description="Central API for honeypot data processing and USB drop beacon reception.",
    version="0.1.0"
)

# Füge die Router zur Hauptanwendung hinzu
app.include_router(honeypot_router, prefix="/analyze") # Beispiel-Prefix für Honeypot-Analysen
app.include_router(usb_drop_router, prefix="/usb")     # Beispiel-Prefix für USB-Drop

@app.get("/")
async def read_root():
    return {"message": "YourProjectName AI Backend API is running!"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)