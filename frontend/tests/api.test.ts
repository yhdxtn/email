import {describe,it,expect,vi,afterEach} from 'vitest';
import {api,refreshCsrf} from '../src/api';
afterEach(()=>vi.unstubAllGlobals());
describe('Same-origin API transport',()=>{
 it('rejects a protocol-relative endpoint',async()=>{await expect(api('//evil.example/')).rejects.toThrow('same-origin');});
 it('uses CSRF and a caller-supplied stable idempotency key',async()=>{
   const fetch=vi.fn().mockResolvedValueOnce({ok:true,json:async()=>({token:'test-only-valid-csrf-token'})}).mockResolvedValueOnce({ok:true,json:async()=>({status:'queued'})});
   vi.stubGlobal('fetch',fetch);await refreshCsrf();await api('/mailboxes','POST',{address:'a@example.test'},'test-only-stable-key');
   const [url,options]=fetch.mock.calls[1];expect(url).toBe('/api/v1/mailboxes');expect(options.headers['X-XSRF-TOKEN']).toBe('test-only-valid-csrf-token');expect(options.headers['Idempotency-Key']).toBe('test-only-stable-key');expect(options.credentials).toBe('same-origin');expect(options.redirect).toBe('error');
 });
 it('coalesces concurrent CSRF refreshes and rejects malformed tokens',async()=>{
   let release!:(value:{ok:boolean;status:number;json:()=>Promise<{token:string}>})=>void;
   const response=new Promise<{ok:boolean;status:number;json:()=>Promise<{token:string}>}>(resolve=>{release=resolve;});
   const fetch=vi.fn().mockReturnValue(response);vi.stubGlobal('fetch',fetch);
   const first=refreshCsrf(),second=refreshCsrf();expect(fetch).toHaveBeenCalledTimes(1);
   release({ok:true,status:200,json:async()=>({token:'test-only-shared-csrf-token'})});
   await Promise.all([first,second]);
   vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:true,status:200,json:async()=>({token:''})}));
   await expect(refreshCsrf()).rejects.toMatchObject({code:'CSRF_INVALID'});
 });
 it('reports CSRF network failure and permits a later retry',async()=>{
   const fetch=vi.fn().mockRejectedValueOnce(new TypeError('network')).mockResolvedValueOnce({ok:true,status:200,json:async()=>({token:'test-only-retried-csrf-token'})});
   vi.stubGlobal('fetch',fetch);
   await expect(refreshCsrf()).rejects.toMatchObject({code:'CSRF_UNAVAILABLE',status:0});
   await expect(refreshCsrf()).resolves.toBeUndefined();expect(fetch).toHaveBeenCalledTimes(2);
 });
 it('does not turn a server error into mock success',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,status:503,json:async()=>({code:'AGENT_OFFLINE',message:'离线'})}));await expect(api('/nodes')).rejects.toMatchObject({code:'AGENT_OFFLINE'});});
});
