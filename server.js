const express = require("express");
const crypto = require("crypto");
const path = require("path");
const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_EVENTS = Number(process.env.MAX_CALLBACK_EVENTS || 500);
const CALLBACK_TOKEN = process.env.CALLBACK_TOKEN || "";
const events = [];
app.disable("x-powered-by");
app.use(express.json({limit:"1mb", verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf)}}));
app.use(express.static(path.join(__dirname,"public")));
function addEvent(req,status="received"){
 const event={id:crypto.randomUUID(),receivedAt:new Date().toISOString(),method:req.method,path:req.originalUrl,ip:req.ip,
 headers:Object.fromEntries(Object.entries(req.headers).filter(([k])=>!["authorization","cookie","set-cookie"].includes(k.toLowerCase()))),body:req.body??null,status};
 events.unshift(event); if(events.length>MAX_EVENTS) events.length=MAX_EVENTS; return event;
}
app.get("/health",(req,res)=>res.json({ok:true,service:"quest-game-playground"}));
app.get("/api/callbacks",(req,res)=>res.json({data:events}));
app.delete("/api/callbacks",(req,res)=>{events.length=0;res.json({ok:true})});
function callback(req,res,provider){
 if(CALLBACK_TOKEN&&req.get("x-callback-token")!==CALLBACK_TOKEN){addEvent(req,"rejected");return res.status(401).json({ok:false,error:"INVALID_CALLBACK_TOKEN"})}
 const event=addEvent(req);res.status(200).json({ok:true,received:true,...(provider?{provider}:{}),event_id:event.id});
}
app.all("/callbacks",(req,res)=>callback(req,res,null));
app.all("/callbacks/:provider",(req,res)=>callback(req,res,req.params.provider));
app.post("/api/proxy",async(req,res)=>{
 const {baseUrl,operatorKey,operatorSecret,method,apiPath,payload}=req.body||{};
 if(!baseUrl||!operatorKey||!operatorSecret||!method||!apiPath)return res.status(400).json({error:"Missing required request settings."});
 let target,base;
 try{
  base=new URL(baseUrl); target=new URL(apiPath,base.href.endsWith("/")?base.href:base.href+"/");
  if(target.origin!==base.origin)throw new Error("Target origin must match API base URL.");
 }catch(e){return res.status(400).json({error:"Invalid API URL/path: "+e.message})}
 const verb=String(method).toUpperCase(),bodyText=["GET","HEAD"].includes(verb)?"":JSON.stringify(payload??{});
 const timestamp=String(Math.floor(Date.now()/1000)),nonce=crypto.randomUUID().replaceAll("-","");
 const canonical=[verb,target.pathname,timestamp,nonce,crypto.createHash("sha256").update(bodyText).digest("hex")].join("\n");
 const signature=crypto.createHmac("sha256",operatorSecret).update(canonical).digest("hex");
 const headers={"Accept":"application/json","X-Operator-Key":operatorKey,"X-1Q-Timestamp":timestamp,"X-1Q-Nonce":nonce,"X-1Q-Signature":signature};
 const isLaunch=verb==="POST" && target.pathname.replace(/\/+$/, "")==="/api/v1/launches";
 const idempotencyKey=isLaunch ? (String(req.body?.idempotencyKey||"").trim() || crypto.randomUUID()) : "";
 if(isLaunch)headers["Idempotency-Key"]=idempotencyKey;
 if(bodyText)headers["Content-Type"]="application/json";
 try{
  const upstream=await fetch(target,{method:verb,headers,body:bodyText||undefined,signal:AbortSignal.timeout(30000)});
  const raw=await upstream.text();let data;try{data=JSON.parse(raw)}catch{data=raw}
  res.status(200).json({upstreamStatus:upstream.status,url:target.toString(),...(isLaunch?{idempotencyKey}:{}),data});
 }catch(e){res.status(502).json({error:"API request failed",detail:e.message})}
});
app.listen(PORT,"0.0.0.0",()=>console.log(`Quest Game Playground listening on ${PORT}`));
