const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_EVENTS = Math.max(1, Number(process.env.MAX_CALLBACK_EVENTS || 500));
const CALLBACK_CONFIG_FILE = path.join(__dirname, "data", "callback-config.json");
let CALLBACK_SECRET = process.env.CALLBACK_SECRET || "";
if (!CALLBACK_SECRET) { try { CALLBACK_SECRET = String(JSON.parse(fs.readFileSync(CALLBACK_CONFIG_FILE, "utf8")).secret || ""); } catch {} }
const DEFAULT_BALANCE = process.env.CALLBACK_DEFAULT_BALANCE || "100.0000";
const events = [];
const wallets = new Map();
const idempotency = new Map();
const callbackNonces = new Map();

app.disable("x-powered-by");
app.use(express.json({limit:"1mb", verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf)}}));
app.use(express.static(path.join(__dirname,"public")));

function sortDeep(value) {
 if (Array.isArray(value)) return value.map(sortDeep);
 if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k=>[k,sortDeep(value[k])]));
 return value;
}
function canonicalJson(value) { return JSON.stringify(sortDeep(value)); }
function safeHeaders(headers) {
 const blocked = new Set(["authorization","cookie","set-cookie","x-1q-signature"]);
 return Object.fromEntries(Object.entries(headers).filter(([k])=>!blocked.has(k.toLowerCase())));
}
function addEvent(req, {status, operation, player, currency, amount, balanceBefore, balanceAfter, responseCode, body}={}) {
 const event={id:crypto.randomUUID(),receivedAt:new Date().toISOString(),method:req.method,path:req.path,ip:req.ip,
  headers:safeHeaders(req.headers),operation:operation||"UNKNOWN",player:player||null,currency:currency||null,amount:amount??null,
  balanceBefore:balanceBefore??null,balanceAfter:balanceAfter??null,status:status||"received",responseCode:responseCode||null,body:body??req.body??null};
 events.unshift(event); if(events.length>MAX_EVENTS)events.length=MAX_EVENTS; return event;
}
function parseAmount(value) {
 const s=String(value??"");
 if(!/^(0|[1-9]\d*)(?:\.\d{1,4})?$/.test(s)) return null;
 const [whole,frac=""]=s.split(".");
 const units=BigInt(whole)*10000n+BigInt((frac+"0000").slice(0,4));
 return units;
}
function formatAmount(units) {
 const negative=units<0n; const n=negative?-units:units;
 return (negative?"-":"")+(n/10000n).toString()+"."+(n%10000n).toString().padStart(4,"0");
}
function walletKey(user,currency) { return String(currency).toUpperCase()+":"+String(user); }
function getBalance(user,currency) {
 const key=walletKey(user,currency);
 if(!wallets.has(key)) {
  const initial=parseAmount(DEFAULT_BALANCE);
  wallets.set(key,initial===null?1000000n:initial);
 }
 return wallets.get(key);
}
function errorResponse(req,res,status,code,message,body=req.body) {
 addEvent(req,{status:"rejected",operation:body?.type||body?.transaction?.type||"UNKNOWN",player:body?.user_code,currency:body?.currency||body?.transaction?.currency||body?.slot?.currency,responseCode:code,body});
 return res.status(status).json({accepted:false,status:"rejected",error_code:code,message});
}
function verifyCallback(req) {
 if(!CALLBACK_SECRET) return {ok:false,status:503,code:"CALLBACK_NOT_CONFIGURED",message:"Configure CALLBACK_SECRET com o segredo de assinatura do callback financeiro da 1Q."};
 const key=String(req.get("X-1Q-Key")||"");
 const timestamp=String(req.get("X-1Q-Timestamp")||"");
 const nonce=String(req.get("X-1Q-Nonce")||"");
 const idem=String(req.get("X-1Q-Idempotency-Key")||"");
 const signature=String(req.get("X-1Q-Signature")||"");
 if(!key||!/^\d{10,13}$/.test(timestamp)||!nonce||nonce.length>128||!idem||idem.length>128||! /^[a-f0-9]{64}$/i.test(signature))
  return {ok:false,status:401,code:"INVALID_CALLBACK_HEADERS",message:"Cabeçalhos de assinatura ou idempotência ausentes/inválidos."};
 const seconds=Number(timestamp.length>10?Math.floor(Number(timestamp)/1000):Number(timestamp));
 if(!Number.isFinite(seconds)||Math.abs(Math.floor(Date.now()/1000)-seconds)>300)
  return {ok:false,status:401,code:"CALLBACK_TIMESTAMP_EXPIRED",message:"Timestamp do callback fora da janela de 5 minutos."};
 const canonical=["POST",req.path,timestamp,nonce,idem,crypto.createHash("sha256").update(canonicalJson(req.body||{})).digest("hex")].join("\n");
 const expected=crypto.createHmac("sha256",CALLBACK_SECRET).update(canonical).digest("hex");
 if(!crypto.timingSafeEqual(Buffer.from(expected,"hex"),Buffer.from(signature.toLowerCase(),"hex")))
  return {ok:false,status:401,code:"INVALID_CALLBACK_SIGNATURE",message:"Assinatura HMAC do callback inválida."};
 const now=Date.now();
 for(const [seen,expires] of callbackNonces) if(expires<=now)callbackNonces.delete(seen);
 const nonceKey=key+":"+nonce;
 if(callbackNonces.has(nonceKey)) return {ok:false,status:409,code:"CALLBACK_NONCE_REPLAY",message:"Nonce já utilizado; cada tentativa precisa de uma assinatura nova."};
 callbackNonces.set(nonceKey,now+300000);
 return {ok:true,nonce,idem};
}
app.get("/health",(req,res)=>res.json({ok:true,service:"quest-game-playground",financialCallback:{configured:Boolean(CALLBACK_SECRET),endpoint:"/callbacks/1q",mode:"in-memory-demo-wallet"}}));
app.get("/api/callbacks",(req,res)=>res.json({data:events,configured:Boolean(CALLBACK_SECRET),endpoint:"/callbacks/1q",wallets:wallets.size}));
app.post("/api/callback-config",(req,res)=>{
 const origin=req.get("Origin");
 if(origin){try{if(new URL(origin).host!==req.get("host"))return res.status(403).json({error:"Origem da solicitação inválida."});}catch{return res.status(403).json({error:"Origem da solicitação inválida."});}}
 const secret=String(req.body?.secret||"");
 if(secret.length<16||secret.length>4096) return res.status(422).json({error:"O segredo precisa ter entre 16 e 4096 caracteres."});
 if(CALLBACK_SECRET && req.body?.currentSecret !== CALLBACK_SECRET) return res.status(403).json({error:"Informe o segredo atual para alterar a configuração."});
 try { fs.mkdirSync(path.dirname(CALLBACK_CONFIG_FILE),{recursive:true}); fs.writeFileSync(CALLBACK_CONFIG_FILE,JSON.stringify({secret,updatedAt:new Date().toISOString()}),{mode:0o600}); CALLBACK_SECRET=secret; return res.json({ok:true,configured:true}); }
 catch(e) { return res.status(500).json({error:"Não foi possível salvar a configuração no servidor."}); }
});
app.delete("/api/callbacks",(req,res)=>{events.length=0;res.json({ok:true})});
app.post("/callbacks/1q",(req,res)=>{
 const verified=verifyCallback(req);
 if(!verified.ok) return errorResponse(req,res,verified.status,verified.code,verified.message);
 const payload=req.body||{};
 const rawType=String(payload.type||payload.transaction?.type||"").toUpperCase().replace(/[\s_-]/g,"");
 const type=rawType==="WINBET"?"WINBET":rawType;
 const user=String(payload.user_code||"");
 const transaction=payload.transaction&&typeof payload.transaction==="object"?payload.transaction:{};
 const slot=payload.slot&&typeof payload.slot==="object"?payload.slot:{};
 const currency=String(payload.currency||transaction.currency||slot.currency||"").toUpperCase();
 if(!user||!/^[A-Z]{3}$/.test(currency)) return errorResponse(req,res,422,"INVALID_CALLBACK_PAYLOAD","user_code e currency ISO de 3 letras são obrigatórios.");
 const idemKey=verified.idem;
 const payloadHash=crypto.createHash("sha256").update(canonicalJson(payload)).digest("hex");
 const previous=idempotency.get(idemKey);
 if(previous) {
  if(previous.payloadHash!==payloadHash) return errorResponse(req,res,409,"IDEMPOTENCY_CONFLICT","A mesma chave de idempotência foi reutilizada com outro payload.");
  addEvent(req,{status:"replayed",operation:type,player:user,currency,responseCode:"IDEMPOTENT_REPLAY",body:payload});
  return res.status(200).json(previous.response);
 }
 const key=walletKey(user,currency);
 let before=getBalance(user,currency),after=before,amount=null,response;
 if(type==="BALANCE") {
  response={status:"success",balance:formatAmount(before),currency};
 } else if(type==="WINBET") {
  const bet=parseAmount(slot.bet),win=parseAmount(slot.win);
  if(bet===null||win===null||bet<=0n) return errorResponse(req,res,422,"INVALID_WINBET_AMOUNT","slot.bet e slot.win precisam ser valores decimais não negativos e bet maior que zero.");
  amount={bet:formatAmount(bet),win:formatAmount(win)};
  if(before<bet) return errorResponse(req,res,422,"INSUFFICIENT_FUNDS","Saldo insuficiente para a aposta.");
  after=before-bet+win;
  response={accepted:true,status:"applied",operator_transaction_id:String(slot.txn_id||idemKey),balance_before:formatAmount(before),balance_after:formatAmount(after),currency};
 } else if(["BET","WIN","REFUND"].includes(type)) {
  const raw=transaction.amount;
  const units=parseAmount(raw);
  if(units===null||units<=0n) return errorResponse(req,res,422,"INVALID_TRANSACTION_AMOUNT","transaction.amount precisa ser um decimal positivo.");
  amount=formatAmount(units);
  if(type==="BET") {
   if(before<units) return errorResponse(req,res,422,"INSUFFICIENT_FUNDS","Saldo insuficiente para a aposta.");
   after=before-units;
  } else after=before+units;
  response={accepted:true,status:"applied",operator_transaction_id:String(transaction.id||idemKey),balance_before:formatAmount(before),balance_after:formatAmount(after),currency};
 } else {
  return errorResponse(req,res,422,"UNSUPPORTED_CALLBACK_TYPE","Operação não suportada pelo callback financeiro da 1Q.");
 }
 if(type!=="BALANCE")wallets.set(key,after);
 idempotency.set(idemKey,{payloadHash,response});
 addEvent(req,{status:"processed",operation:type,player:user,currency,amount,balanceBefore:formatAmount(before),balanceAfter:formatAmount(after),responseCode:"200",body:payload});
 return res.status(200).json(response);
});
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
  res.status(upstream.status).json({upstreamStatus:upstream.status,url:target.toString(),...(isLaunch?{idempotencyKey}:{}),data});
 }catch(e){res.status(502).json({error:"API request failed",detail:e.message})}
});
app.listen(PORT,"0.0.0.0",()=>console.log(`Quest Game Playground listening on ${PORT}`));
