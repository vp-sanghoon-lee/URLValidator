import asyncio
import logging
from fastapi import FastAPI,HTTPException,status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Literal, Optional
import settings
import httpx

class ScanRequest(BaseModel):
    url: str
    detail: Optional[bool] = False

class ScanResult(BaseModel):
    url: str
    verdict: Literal["clean","unrated"]

class EngineStats(BaseModel):
    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("URLValidator")

app = FastAPI(
    title = "URLValidator API",
    version = "1.0.0",
    description = "브이피(주) 후후서비스 URL검사 API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],             # 예: ["https://your-frontend.example.com"]
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def request_headers()->dict:
    return {"x-apikey":settings.VT_APIKEY}

async def vt_submit_url(client:httpx.AsyncClient,url:str)->str:
    resp = await client.post(f"{settings.VT_BASEURL}/urls",data={"url":url},headers=request_headers(),timeout=5.0)
    if resp.status_code>=400:
        raise HTTPException(status_code=resp.status_code,details=resp.text)

    return resp.json()['data']['id']
    
async def vt_get_analysis(client: httpx.AsyncClient, analysis_id: str)->dict:
    resp = await client.get(f"{settings.VT_BASEURL}/analyses/{analysis_id}", headers=request_headers(), timeout=5.0)
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    
    return resp.json()

def parse_stats(stats: dict) -> EngineStats:
    return EngineStats(
        harmless=int(stats.get("harmless", 0)),
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        undetected=int(stats.get("undetected", 0)),
        timeout=int(stats.get("timeout", 0)),
    )

def verdict_from_stats(stats: dict) -> str:
    m = int(stats.get("malicious", 0))
    s = int(stats.get("suspicious", 0))
    h = int(stats.get("harmless", 0))
    if m > 0: 
        return "악성"
    if s > 0: 
        return "주의"
    if h > 0 and m == 0 and s == 0: 
        return "정상"
    
    return "주의"

@app.post("/urlvalidator/scan")
async def scan(req:ScanRequest):
    timeout = settings.VT_POLL_TIMEOUT_SEC

    async with httpx.AsyncClient() as client:
        try:
            analysis_id = await vt_submit_url(client,req.url)
            logger.info(f"\t{analysis_id}")
        except HTTPException:
            raise

        deadline = asyncio.get_event_loop().time() + timeout
        last_stats = None

        while True:
            data = await vt_get_analysis(client,analysis_id)
            status_str = data.get("data", {}).get("attributes", {}).get("status", "")
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            logger.info(status_str)
            last_stats = stats or last_stats
            if status_str == "completed":
                break

            if asyncio.get_event_loop().time() >= deadline:
                # 타임아웃: 현재까지 수집된 통계로 응답
                break

            await asyncio.sleep(settings.VT_POLL_INTERVAL_SEC)

    return {"url":req.url,"source":"vt","result":verdict_from_stats(stats),"details":data}

@app.get("/urlvalidator/health")
async def health():
    return {"urlvalidator":True}