const response=(status,error,retry)=>Response.json({error},{status,headers:{'Cache-Control':'no-store',...(retry?{'Retry-After':String(retry)}:{})}});
async function consume(db,key,limit,seconds){
 const now=Math.floor(Date.now()/1000);
 const row=await db.prepare(`INSERT INTO rate_limits(key,attempts,expires_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN expires_at<=? THEN 1 ELSE MIN(attempts+1,?) END, expires_at=CASE WHEN expires_at<=? THEN excluded.expires_at ELSE expires_at END RETURNING attempts,expires_at`).bind(key,now+seconds,now,limit+1,now).first();
 if(!row)throw Error('rate limit unavailable');
 return row.attempts>limit?Math.max(1,row.expires_at-now):0;
}
export async function onRequest(c){
 const path=new URL(c.request.url).pathname.replace(/\/+$/,'');
 const method=c.request.method;
 const checkout=path==='/api/orders'&&method==='POST';
 const admin=(path==='/api/orders'&&['GET','PATCH','DELETE','HEAD'].includes(method))||(path==='/api/products'&&method==='PUT')||(path==='/api/product-image'&&method==='POST')||(path==='/api/receipt'&&['GET','HEAD'].includes(method));
 if(!checkout&&!admin)return c.next();
 try{
  const ip=c.request.headers.get('CF-Connecting-IP');
  if(!ip)return response(503,'security unavailable');
  const key=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ip)))).map(x=>x.toString(16).padStart(2,'0')).join('');
  if(admin){
   if(!c.env.ADMIN_PASSWORD)return response(503,'security unavailable');
   const now=Math.floor(Date.now()/1000);
   const row=await c.env.DB.prepare('SELECT attempts,expires_at FROM rate_limits WHERE key=?').bind('admin:'+key).first();
   if(row&&row.attempts>=5&&row.expires_at>now)return response(429,'too many attempts',row.expires_at-now);
   if(c.request.headers.get('Authorization')!=='Bearer '+c.env.ADMIN_PASSWORD){
    const retry=await consume(c.env.DB,'admin:'+key,5,900);
    return retry?response(429,'too many attempts',retry):response(401,'unauthorized');
   }
  }else{
   const retry=await consume(c.env.DB,'checkout:'+key,5,60);
   if(retry)return response(429,'too many requests',retry);
  }
  if(Math.random()<0.02)c.waitUntil(c.env.DB.prepare('DELETE FROM rate_limits WHERE expires_at<=?').bind(Math.floor(Date.now()/1000)).run().catch(()=>{}));
 }catch{return response(503,'security unavailable');}
 return c.next();
}
