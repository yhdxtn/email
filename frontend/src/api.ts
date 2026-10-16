export class ApiFailure extends Error {
  constructor(public code:string,message:string,public status:number,public requestId?:string){super(message);this.name='ApiFailure';}
}
let csrfToken='';
let csrfRefresh:Promise<void>|null=null;
export function refreshCsrf():Promise<void>{
  if(csrfRefresh)return csrfRefresh;
  csrfRefresh=(async()=>{
    let response:Response;
    try{response=await fetch('/api/v1/auth/csrf',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});}
    catch{throw new ApiFailure('CSRF_UNAVAILABLE','无法连接管理后台，请检查服务后重试。',0);}
    if(!response.ok)throw new ApiFailure('CSRF_UNAVAILABLE','无法初始化安全会话，请检查后端连接。',response.status);
    const body=await response.json().catch(()=>null);
    if(!body||typeof body!=='object'||typeof body.token!=='string'||body.token.length<16||body.token.length>256)throw new ApiFailure('CSRF_INVALID','服务器未返回有效的安全令牌。',response.status);
    csrfToken=body.token;
  })().finally(()=>{csrfRefresh=null;});
  return csrfRefresh;
}
/** No credentials/tokens in localStorage; cookies are HttpOnly, issued by the server. */
export async function api<T=Record<string,unknown>>(path:string,method='GET',body?:unknown,key?:string):Promise<T>{
  if(!path.startsWith('/')||path.startsWith('//'))throw new Error('Only same-origin API paths are allowed');
  if(method!=='GET'&&!csrfToken)await refreshCsrf();
  const headers:Record<string,string>={Accept:'application/json'};
  if(body!==undefined)headers['Content-Type']='application/json';
  if(method!=='GET')headers['X-XSRF-TOKEN']=csrfToken;
  if(key)headers['Idempotency-Key']=key;
  let response:Response;
  try{response=await fetch('/api/v1'+path,{method,body:body===undefined?undefined:JSON.stringify(body),headers,credentials:'same-origin',cache:'no-store',redirect:'error'});}
  catch{throw new ApiFailure('NETWORK_UNAVAILABLE','无法连接管理后台。请求可能已执行，请先查看任务，勿重复提交。',0);}
  const result=await response.json().catch(()=>({code:'INVALID_SERVER_RESPONSE',message:'服务器未返回预期的 JSON 响应。'}));
  if(!response.ok){if(response.status===401)csrfToken='';throw new ApiFailure(result.code||'REQUEST_FAILED',result.message||'请求失败',response.status,result.requestId);}
  return result as T;
}
export function idempotencyKey():string{return crypto.randomUUID();}
