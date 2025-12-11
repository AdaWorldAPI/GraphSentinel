"""
GraphSentinel - AI-Powered Security Operations Center
LangChain threat analysis + Auto-remediation + ElevenLabs voice alerts
"""
import os
import json
import httpx
import asyncio
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="GraphSentinel",
    description="AI-Powered Security Operations - Threat Analysis & Voice Alerts",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
ELEVENLABS_KEY = os.getenv("ELEVENLABS_KEY", "")
ELEVENLABS_VOICE = os.getenv("ELEVENLABS_VOICE", "21m00Tcm4TlvDq8ikWAM")  # Rachel
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")

# In-memory state for demo
threat_log = []
remediation_log = []


class ThreatAlert(BaseModel):
    """Incoming threat alert."""
    source: str = "Defender"
    alert_type: str = "BruteForce"
    severity: str = "High"
    details: dict = {}


class AdaAnalysis(BaseModel):
    """Ada's threat analysis result."""
    threat_id: str
    summary: str
    reasoning: list[str]
    risk_score: int
    recommended_actions: list[str]
    auto_remediated: bool
    voice_message: Optional[str] = None


async def ada_analyze_threat(alert: ThreatAlert) -> AdaAnalysis:
    """Ada Hive Mind analyzes the threat."""
    
    # Simulated reasoning chain (would be LangChain in production)
    threat_id = f"THR-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    reasoning = [
        f"🔍 Detected {alert.alert_type} from {alert.source}",
        f"📊 Analyzing patterns... {alert.details.get('attempts', 'multiple')} attempts detected",
        f"🌍 GeoIP lookup: Origins from {alert.details.get('origins', 'unknown regions')}",
        f"🧠 Correlating with knowledge graph...",
        f"⚡ Risk assessment: {alert.severity} severity confirmed",
        f"🛡️ Checking available remediation options...",
    ]
    
    # Determine actions based on alert type
    actions = []
    if alert.alert_type == "BruteForce":
        actions = [
            "Block source IPs in Conditional Access",
            "Enable MFA enforcement for targeted accounts",
            "Increase sign-in risk policy to High",
            "Notify security team via voice alert"
        ]
    elif alert.alert_type == "ImpossibleTravel":
        actions = [
            "Require re-authentication",
            "Enable location-based Conditional Access",
            "Flag session for review"
        ]
    elif alert.alert_type == "MalwareDetected":
        actions = [
            "Isolate affected device",
            "Revoke active sessions",
            "Trigger Defender scan",
            "Alert SOC team"
        ]
    
    return AdaAnalysis(
        threat_id=threat_id,
        summary=f"{alert.alert_type} attack detected - Auto-remediation initiated",
        reasoning=reasoning,
        risk_score=85 if alert.severity == "High" else 60,
        recommended_actions=actions,
        auto_remediated=True
    )


async def generate_voice_alert(analysis: AdaAnalysis, alert: ThreatAlert) -> bytes:
    """Generate voice message via ElevenLabs."""
    
    # Build the voice message
    origins = alert.details.get('origins', 'mehreren Regionen')
    attempts = alert.details.get('attempts', 'tausende')
    
    message = f"""
    Hi, hier ist Ada vom Security Operations Center.
    
    Kurzes Update: In den letzten Stunden gab es {attempts} Login-Versuche 
    aus {origins}.
    
    Ich habe mir erlaubt, die Conditional Access Policy vorübergehend zu verschärfen 
    und MFA auf allen Admin-Accounts zu erzwingen.
    
    Der betroffene Kollege ohne MFA wurde automatisch geschützt - 
    er kann sich Montag bei mir bedanken.
    
    Threat ID ist {analysis.threat_id}. Details im Dashboard.
    
    Schönes Wochenende!
    """
    
    if not ELEVENLABS_KEY:
        return b""
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.elevenlabs.io/v1/text-to-speech/{ELEVENLABS_VOICE}",
            headers={
                "xi-api-key": ELEVENLABS_KEY,
                "Content-Type": "application/json"
            },
            json={
                "text": message,
                "model_id": "eleven_multilingual_v2",
                "voice_settings": {
                    "stability": 0.5,
                    "similarity_boost": 0.75
                }
            },
            timeout=30.0
        )
        if resp.status_code == 200:
            return resp.content
        return b""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Security Operations Dashboard."""
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GraphSentinel - AI Security Ops</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .logo { font-size: 40px; }
        h1 { font-size: 28px; font-weight: 700; color: #fff; }
        .subtitle { color: #888; font-size: 14px; margin-top: 4px; }
        .status-bar {
            display: flex;
            gap: 20px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }
        .status-chip {
            background: rgba(0,255,136,0.1);
            border: 1px solid rgba(0,255,136,0.3);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
            color: #00ff88;
        }
        .status-chip.warning {
            background: rgba(255,170,0,0.1);
            border-color: rgba(255,170,0,0.3);
            color: #ffaa00;
        }
        .status-chip.danger {
            background: rgba(255,68,68,0.1);
            border-color: rgba(255,68,68,0.3);
            color: #ff4444;
        }
        .card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.08);
        }
        .card h3 {
            color: #00d4ff;
            margin-bottom: 16px;
            font-size: 18px;
        }
        .threat-item {
            background: rgba(255,68,68,0.1);
            border-left: 4px solid #ff4444;
            padding: 16px;
            margin-bottom: 12px;
            border-radius: 0 12px 12px 0;
        }
        .threat-item.remediated {
            background: rgba(0,255,136,0.1);
            border-left-color: #00ff88;
        }
        .threat-title { font-weight: 600; margin-bottom: 8px; }
        .threat-meta { font-size: 12px; color: #888; }
        .reasoning-step {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 14px;
        }
        .btn {
            background: linear-gradient(135deg, #ff4444, #cc0000);
            color: #fff;
            border: none;
            padding: 14px 28px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-right: 12px;
            margin-top: 12px;
        }
        .btn.secondary {
            background: linear-gradient(135deg, #00d4ff, #0099cc);
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        #ada-thinking {
            display: none;
            background: rgba(0,212,255,0.1);
            border: 1px solid rgba(0,212,255,0.3);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        #ada-thinking.active { display: block; }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        audio { width: 100%; margin-top: 16px; }
    </style>
</head>
<body>
    <div class="header">
        <span class="logo">🛡️</span>
        <div>
            <h1>GraphSentinel</h1>
            <div class="subtitle">AI-Powered Security Operations Center</div>
        </div>
    </div>

    <div class="status-bar">
        <div class="status-chip">🧠 Ada Hive: Online</div>
        <div class="status-chip">🔊 Voice Alerts: Ready</div>
        <div class="status-chip" id="threat-count">⚠️ Threats: 0</div>
    </div>

    <div class="card">
        <h3>🚨 Simulate Threat</h3>
        <p style="color:#888; margin-bottom:16px;">Trigger a simulated attack to see Ada's response</p>
        <button class="btn" onclick="simulateBruteForce()">🔐 Brute Force Attack</button>
        <button class="btn secondary" onclick="simulateImpossibleTravel()">✈️ Impossible Travel</button>
    </div>

    <div id="ada-thinking" class="card">
        <h3 class="pulse">🧠 Ada is analyzing...</h3>
        <div id="reasoning-steps"></div>
    </div>

    <div class="card">
        <h3>📋 Threat Log</h3>
        <div id="threat-log">
            <p style="color:#666; text-align:center; padding:20px;">No threats detected. Simulate one above.</p>
        </div>
    </div>

    <div class="card" id="voice-card" style="display:none;">
        <h3>🔊 Ada Voice Alert</h3>
        <audio id="voice-audio" controls></audio>
    </div>

    <script>
        async function simulateBruteForce() {
            await triggerThreat({
                source: "Microsoft Defender",
                alert_type: "BruteForce",
                severity: "High",
                details: {
                    attempts: "15.000",
                    origins: "Korea, China und Russland",
                    target: "Admin Accounts"
                }
            });
        }

        async function simulateImpossibleTravel() {
            await triggerThreat({
                source: "Azure AD Identity Protection",
                alert_type: "ImpossibleTravel",
                severity: "Medium",
                details: {
                    user: "admin@contoso.com",
                    locations: "Frankfurt → Tokyo in 10 minutes",
                    origins: "verdächtigen Standorten"
                }
            });
        }

        async function triggerThreat(alert) {
            const thinkingEl = document.getElementById('ada-thinking');
            const stepsEl = document.getElementById('reasoning-steps');
            
            thinkingEl.classList.add('active');
            stepsEl.innerHTML = '';

            try {
                const resp = await fetch('/api/threat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(alert)
                });
                const data = await resp.json();

                // Animate reasoning steps
                for (let i = 0; i < data.reasoning.length; i++) {
                    await new Promise(r => setTimeout(r, 500));
                    stepsEl.innerHTML += `<div class="reasoning-step">${data.reasoning[i]}</div>`;
                }

                await new Promise(r => setTimeout(r, 500));
                thinkingEl.classList.remove('active');

                // Update threat log
                updateThreatLog(data, alert);

                // Show voice if available
                if (data.voice_url) {
                    document.getElementById('voice-card').style.display = 'block';
                    document.getElementById('voice-audio').src = data.voice_url;
                }

            } catch (e) {
                thinkingEl.classList.remove('active');
                alert('Error: ' + e.message);
            }
        }

        function updateThreatLog(analysis, alert) {
            const logEl = document.getElementById('threat-log');
            const countEl = document.getElementById('threat-count');
            
            const html = `
                <div class="threat-item remediated">
                    <div class="threat-title">${analysis.threat_id}: ${alert.alert_type}</div>
                    <div class="threat-meta">
                        Source: ${alert.source} | Risk: ${analysis.risk_score}/100 | 
                        Status: ✅ Auto-remediated
                    </div>
                    <div style="margin-top:12px; font-size:14px;">
                        <strong>Actions taken:</strong><br>
                        ${analysis.recommended_actions.map(a => '• ' + a).join('<br>')}
                    </div>
                </div>
            `;
            
            if (logEl.querySelector('p')) {
                logEl.innerHTML = html;
            } else {
                logEl.innerHTML = html + logEl.innerHTML;
            }
            
            const count = logEl.querySelectorAll('.threat-item').length;
            countEl.textContent = '⚠️ Threats: ' + count;
            countEl.className = 'status-chip ' + (count > 0 ? 'warning' : '');
        }
    </script>
</body>
</html>""")


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "operational",
        "service": "GraphSentinel",
        "ada_hive": "online",
        "voice_alerts": bool(ELEVENLABS_KEY),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/threat")
async def process_threat(alert: ThreatAlert, background_tasks: BackgroundTasks):
    """Process incoming threat alert through Ada Hive."""
    
    # Ada analyzes
    analysis = await ada_analyze_threat(alert)
    
    # Log it
    threat_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": alert.dict(),
        "analysis": analysis.dict()
    })
    
    # Generate voice alert
    voice_url = None
    if ELEVENLABS_KEY:
        audio_bytes = await generate_voice_alert(analysis, alert)
        if audio_bytes:
            # In production: upload to S3/storage and return URL
            # For demo: we'll use a separate endpoint
            voice_url = f"/api/voice/{analysis.threat_id}"
            # Store temporarily (in production use Redis/S3)
            app.state.__dict__[f"voice_{analysis.threat_id}"] = audio_bytes
    
    return {
        **analysis.dict(),
        "voice_url": voice_url
    }


@app.get("/api/voice/{threat_id}")
async def get_voice_alert(threat_id: str):
    """Get generated voice alert audio."""
    audio_key = f"voice_{threat_id}"
    audio_bytes = app.state.__dict__.get(audio_key)
    
    if not audio_bytes:
        return JSONResponse({"error": "Voice not found"}, status_code=404)
    
    from fastapi.responses import Response
    return Response(content=audio_bytes, media_type="audio/mpeg")


@app.get("/api/threats")
async def get_threats():
    """Get threat log."""
    return {"threats": threat_log[-50:]}  # Last 50


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
