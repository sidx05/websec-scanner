"""
FastAPI REST API for local scanning.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
import shutil
from pathlib import Path

from main import WebsiteScanner
from storage_utils import save_report_and_history, read_history
from scan_queue import ScanQueue
from file_analyzer import FileAnalyzer
from dashboard_api import dashboard_app
from recommendations import generate_recommendations, format_recommendations_text
from compliance import ComplianceChecker, format_compliance_report

app = FastAPI(title="Website Security Scanner API")
scan_queue = ScanQueue()


class ScanRequest(BaseModel):
    url: str
    save: Optional[bool] = True


class EnqueueRequest(BaseModel):
    url: str
    save: Optional[bool] = True


@app.post("/scan")
def scan(req: ScanRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="Missing url")
    scanner = WebsiteScanner()
    results = scanner.scan(req.url)
    if 'error' in results:
        raise HTTPException(status_code=400, detail=str(results['error']))
    if req.save:
        save_report_and_history(results)
    return results


@app.get("/history")
def history(limit: int = 50):
    return read_history(limit)


@app.post("/enqueue")
def enqueue(req: EnqueueRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="Missing url")
    job_id = scan_queue.enqueue(req.url, save=req.save if req.save is not None else True)
    return {"job_id": job_id, "state": "queued"}


@app.get("/queue")
def queue_status(job_id: Optional[str] = None):
    return scan_queue.get_status(job_id)


@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze uploaded file for security metadata."""
    # Save temporarily
    temp_dir = Path('temp')
    temp_dir.mkdir(exist_ok=True)
    temp_path = temp_dir / file.filename
    
    try:
        with temp_path.open('wb') as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        analyzer = FileAnalyzer(str(temp_path))
        result = analyzer.analyze()
        
        return result
    finally:
        if temp_path.exists():
            temp_path.unlink()


@app.post("/scan/recommendations")
def get_recommendations(req: ScanRequest):
    """Scan URL and return only recommendations."""
    if not req.url:
        raise HTTPException(status_code=400, detail="Missing url")
    scanner = WebsiteScanner()
    results = scanner.scan(req.url)
    if 'error' in results:
        raise HTTPException(status_code=400, detail=str(results['error']))
    return {
        'url': req.url,
        'recommendations': results.get('recommendations', []),
        'text': format_recommendations_text(results.get('recommendations', []))
    }


@app.post("/scan/compliance")
def get_compliance(req: ScanRequest):
    """Scan URL and return compliance report."""
    if not req.url:
        raise HTTPException(status_code=400, detail="Missing url")
    scanner = WebsiteScanner()
    results = scanner.scan(req.url)
    if 'error' in results:
        raise HTTPException(status_code=400, detail=str(results['error']))
    return {
        'url': req.url,
        'compliance': results.get('compliance', {}),
        'text': format_compliance_report(results.get('compliance', {}))
    }


# Mount dashboard API
app.mount("/dashboard", dashboard_app)

@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Website Security Scanner API",
        "features": [
            "POST /scan - Scan single URL",
            "GET /history - Scan history",
            "POST /enqueue - Queue scan job",
            "GET /queue - Queue status",
            "POST /analyze-file - File security analysis",
            "POST /scan/recommendations - Get recommendations only",
            "POST /scan/compliance - Get compliance report",
            "GET /dashboard/* - Dashboard analytics API"
        ]
    }


if __name__ == '__main__':
    import uvicorn
    print("=" * 70)
    print("🚀 Website Security Scanner API")
    print("=" * 70)
    print("\n📡 Starting servers:")
    print("  • Main API:      http://127.0.0.1:8002")
    print("  • Dashboard API: http://127.0.0.1:8002/dashboard/overview")
    print("\n📖 Documentation:")
    print("  • Swagger UI: http://127.0.0.1:8002/docs")
    print("  • ReDoc:      http://127.0.0.1:8002/redoc")
    print("\n✨ Key Endpoints:")
    print("  • POST /scan - Scan a website")
    print("  • GET /history - View scan history")
    print("  • POST /scan/recommendations - Get security recommendations")
    print("  • POST /scan/compliance - Get compliance report")
    print("  • GET /dashboard/overview - Dashboard analytics")
    print("\n" + "=" * 70 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8002)