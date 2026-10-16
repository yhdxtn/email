<script setup lang="ts">
import { computed, ref, shallowRef, watch } from 'vue';
import { api, ApiFailure, idempotencyKey } from './api';
import { bytes, time } from './format';
import type { Field, Row, Section } from './types';
import AuthScreen from './components/AuthScreen.vue';
import DataTable from './components/DataTable.vue';
import FormDialog from './components/FormDialog.vue';
import PreviewDialog from './components/PreviewDialog.vue';
const user=ref<Row|null>(null),section=ref<Section>('overview'),loading=ref(false),notice=ref(''),problem=ref(''),lastRefresh=ref('');
const data=ref<Row>({}),rows=ref<Row[]>([]),nodes=ref<Row[]>([]),domains=ref<Row[]>([]),nodeId=ref(''),selectedDomain=ref(''),dnsRecords=ref<Row[]>([]),dnsPlans=ref<Row[]>([]),drills=ref<Row[]>([]);
const query=ref(''),inspected=ref<unknown>(null),mobileMenu=ref(false);
const form=shallowRef<{title:string;description?:string;fields:Field[];submit:(values:Row)=>Promise<void>}|null>(null);
const preview=shallowRef<{plan:Row;confirm?:(confirmation:string,key:string)=>Promise<unknown>}|null>(null);
const attachments=ref<File[]>([]);
const mail=ref({from:'',to:'',subject:'',body:'',html:false});
const nav:{id:Section;label:string;icon:string;roles:string[]}[]=[
 {id:'overview',label:'系统概览',icon:'◈',roles:['Owner','MailAdmin','DnsAdmin','Operator','Auditor']},
 {id:'mailboxes',label:'邮箱账户',icon:'✉',roles:['Owner','MailAdmin','Operator','Auditor']},
 {id:'aliases',label:'别名与转发',icon:'↗',roles:['Owner','MailAdmin','Operator','Auditor']},
 {id:'domains',label:'域名与 DNS',icon:'◎',roles:['Owner','MailAdmin','DnsAdmin','Operator','Auditor']},
 {id:'sending',label:'测试邮件',icon:'➤',roles:['Owner','MailAdmin','Auditor']},
 {id:'queue',label:'投递队列',icon:'≋',roles:['Owner','MailAdmin','Operator','Auditor']},
 {id:'nodes',label:'邮件节点',icon:'▣',roles:['Owner','MailAdmin','Operator','Auditor']},
 {id:'health',label:'健康与告警',icon:'⌁',roles:['Owner','MailAdmin','DnsAdmin','Operator','Auditor']},
 {id:'backups',label:'备份与演练',icon:'◷',roles:['Owner','Operator','Auditor']},
 {id:'tasks',label:'任务记录',icon:'☷',roles:['Owner','MailAdmin','DnsAdmin','Operator','Auditor']},
 {id:'audit',label:'操作审计',icon:'▤',roles:['Owner','Auditor']},
 {id:'website',label:'网站用户',icon:'♙',roles:['Owner','WebsiteUserAdmin','Auditor']},
 {id:'admins',label:'管理员权限',icon:'⌘',roles:['Owner']},
 {id:'settings',label:'系统设置',icon:'⚙',roles:['Owner','Operator','Auditor']},
 {id:'sessions',label:'我的会话',icon:'⏣',roles:['Owner','MailAdmin','DnsAdmin','Operator','Auditor','WebsiteUserAdmin']}
];
const visibleNav=computed(()=>nav.filter(n=>n.roles.includes(user.value?.role)));
const title=computed(()=>nav.find(n=>n.id===section.value)?.label||'控制台');
const filtered=computed(()=>rows.value.filter(row=>JSON.stringify(row).toLowerCase().includes(query.value.toLowerCase())));
const may=(...roles:string[])=>roles.includes(user.value?.role||'');
const canMail=computed(()=>may('Owner','MailAdmin')),canDns=computed(()=>may('Owner','DnsAdmin'));
const nodeOptions=computed(()=>nodes.value.map(row=>({value:row.id,label:row.name+(row.readonly?' · 只读':'')})));
const domainOptions=computed(()=>domains.value.map(row=>({value:row.id,label:row.name})));
const text=(key:string,labelText:string,value='',required=true):Field=>({key,label:labelText,type:'text',required,value});
const password=(key='password',labelText='密码（14–72 字节）'):Field=>({key,label:labelText,type:'password',min:14,max:72,required:true});
const selector=(key:string,labelText:string,options:{value:string;label:string}[],value=''):Field=>({key,label:labelText,type:'select',required:true,options,value});
const freshFields=():Field[]=>[password('__password','当前管理员密码')];
async function fresh(values:Row){await api('/auth/reauth','POST',{password:values.__password});delete values.__password;}
function explain(error:unknown){problem.value=error instanceof ApiFailure?`${error.message} [${error.code}]${error.requestId?' · 请求 '+error.requestId:''}`:error instanceof Error?error.message:'操作失败';}
async function perform(work:()=>Promise<unknown>,success='已提交，请检查任务或状态。'){
  problem.value='';notice.value='';try{await work();notice.value=success;await load();}catch(error){explain(error);}
}
function openForm(titleText:string,fields:Field[],submit:(values:Row,key:string)=>Promise<unknown>,description?:string){
  const key=idempotencyKey();form.value={title:titleText,description,fields,submit:async values=>{await submit(values,key);notice.value='操作已受理。';await load();}};
}
function inspect(value:unknown){inspected.value=value;}
async function plan(path:string,body?:unknown){await perform(async()=>{const result=await api<Row>(path,'POST',body);preview.value={plan:result};},'请核对变更预览。');}
async function ready(current:Row){user.value=current;section.value=current.role==='WebsiteUserAdmin'?'website':'overview';await load();}
async function logout(){await perform(async()=>{await api('/auth/logout','POST');user.value=null;rows.value=[];data.value={};inspected.value=null;},'已退出');}
async function load(){
  if(!user.value)return;loading.value=true;problem.value='';
  try{
    if(may('Owner','MailAdmin','Operator','Auditor')&&['nodes','domains','mailboxes','aliases','queue','health','backups'].includes(section.value)){nodes.value=await api<Row[]>('/nodes');if(!nodeId.value&&nodes.value[0])nodeId.value=nodes.value[0].id;}
    if(['domains','mailboxes','aliases'].includes(section.value))domains.value=await api<Row[]>('/domains');
    const endpoint:Partial<Record<Section,string>>={mailboxes:'/mailboxes',aliases:'/aliases',sending:'/mail/sends',tasks:'/tasks',audit:'/audit/events',admins:'/admins',sessions:'/auth/sessions',backups:'/backups',health:'/health/checks'};
    if(endpoint[section.value])rows.value=await api<Row[]>(endpoint[section.value]!);
    else if(section.value==='nodes')rows.value=nodes.value;
    else if(section.value==='domains'){rows.value=domains.value;dnsPlans.value=await api<Row[]>('/dns/plans');if(!selectedDomain.value&&domains.value[0])selectedDomain.value=domains.value[0].id;if(selectedDomain.value)await desired();}
    else if(section.value==='queue'){data.value=nodeId.value?await api<Row>(`/mail/queue?nodeId=${nodeId.value}`):{items:[],state:'unknown'};rows.value=data.value.items||[];}
    else if(section.value==='overview')data.value=await api<Row>('/overview');
    else if(section.value==='settings')data.value=await api<Row>('/settings');
    else if(section.value==='website')data.value=await api<Row>('/website-users');
    if(section.value==='backups')drills.value=await api<Row[]>('/restore-drills');
    if(section.value==='health'&&may('Owner','MailAdmin','Operator','Auditor'))data.value={alerts:await api<Row[]>('/alerts')};
    lastRefresh.value=new Date().toLocaleTimeString('zh-CN',{hour12:false});
  }catch(error){explain(error);}finally{loading.value=false;}
}
watch(section,()=>{query.value='';inspected.value=null;rows.value=[];data.value={};mobileMenu.value=false;void load();});
async function desired(){if(selectedDomain.value){const result=await api<Row>(`/domains/${selectedDomain.value}/dns/desired`);dnsRecords.value=result.records;}}
function newNode(){openForm('注册邮件节点',[text('name','节点名称'),text('instanceId','部署中绑定的实例 ID')],v=>api('/nodes','POST',v),'这里只登记连接，不安装、重装或改写邮件服务。Agent 连接地址与密钥只能在部署机配置。');}
function domainFields(row:Row={}):Field[]{return [text('name','邮件域名',row.name||''),text('mailHost','专用邮件主机名',row.mail_host||''),text('publicIpv4','邮件服务器 IPv4',row.public_ipv4||''),text('registrar','域名注册商（不等于 DNS 托管商）',row.registrar||'',false),selector('nodeId','邮件节点',nodeOptions.value,row.node_id||''),text('dkimSelector','DKIM selector',row.dkim_selector||'mail'),{key:'dkimPublic',label:'DKIM 公钥 TXT（不能粘贴私钥）',type:'textarea',value:row.dkim_public||'',max:8192},text('spf','SPF 期望值',row.spf||'v=spf1 mx -all'),text('dmarc','DMARC 期望值',row.dmarc||'v=DMARC1; p=none;'),{key:'ttl',label:'TTL（秒）',type:'number',min:60,max:86400,value:row.ttl||300,required:true}];}
function domainForm(row?:Row){openForm(row?'编辑期望配置':'添加邮件域',domainFields(row),v=>api(row?`/domains/${row.id}`:'/domains',row?'PUT':'POST',v),'保存期望状态不会修改 DNS。域名及节点创建后不可从此入口换绑。');}
async function dnsPlan(){if(!selectedDomain.value)return;await perform(async()=>{const result=await api<Row>(`/domains/${selectedDomain.value}/dns/plan`,'POST');if(result.provider==='manual'||!result.id){inspect(result);notice.value='手动模式：请逐条复制记录到实际 DNS 托管商。';}else{await confirmDns(result.id,'apply');}},'已生成 DNS 预览。');}
async function confirmDns(id:string,mode:'apply'|'rollback'){
  const detail=await api<Row>(`/dns/plans/${id}`);const confirmation=`${mode==='apply'?'APPLY DNS':'ROLLBACK DNS'} ${id}`;
  preview.value={plan:{id,confirmation,preview:{mode,before:detail.before_records,changes:detail.changes,after:detail.after_records,state:detail.state,websiteRecordsProtected:true}},confirm:confirm=>api(`/dns/plans/${id}/${mode}`,'POST',{confirmation:confirm})};
}
function provider(){const domain=domains.value.find(row=>row.id===selectedDomain.value);if(!domain)return;openForm('显式配置 DNS 托管商',[selector('provider','DNS provider',[{value:'manual',label:'手动 DNS'},{value:'cloudflare',label:'Cloudflare'}],domain.provider),{...text('zoneId','Cloudflare Zone ID','',false),hint:'Cloudflare 模式必填，32 位小写十六进制。'},{...password('token','Cloudflare API Token'),required:false,min:20,max:256,hint:'仅使用所选 Zone 的 DNS 编辑权限和 Zone 读取权限；不会回显现有 Token。'},...freshFields()],async v=>{await fresh(v);if(v.provider==='manual'){v.zoneId=null;v.token=null;}return api(`/domains/${domain.id}/dns/provider`,'PUT',v);},'NameSilo 注册并不代表 DNS 托管在 NameSilo。自动写入前会验证实际 NS 与 Zone。');}
function mailboxForm(){openForm('创建邮箱账户',[selector('domainId','邮件域',domainOptions.value),{...text('address','完整邮箱地址'),type:'email'},password(),{key:'quotaBytes',label:'配额（字节）',type:'number',value:1073741824,min:1048576,max:1099511627776,required:true,hint:'1 GiB = 1073741824 字节。'},...freshFields()],async(v,key)=>{await fresh(v);return api('/mailboxes','POST',v,key);},'只有获得本机批准并启用管理的兼容节点可以写入。邮箱密码只转成邮件认证哈希，不保存原文；提交前需重新输入管理员密码。');}
function mailboxAction(row:Row,action:string){
  if(action==='quota'){
    openForm('调整邮箱配额',[{key:'quotaBytes',label:'配额（字节）',type:'number',value:row.quota_bytes,min:1048576,max:1099511627776,required:true},...freshFields()],async(v,key)=>{await fresh(v);return api(`/mailboxes/${row.id}/quota`,'POST',v,key);},`调整 ${row.address} 的配额需要重新认证。`);
  }else if(action==='password-reset'){
    openForm('修改邮箱密码',[password(),...freshFields()],async(v,key)=>{await fresh(v);return api(`/mailboxes/${row.id}/password-reset`,'POST',v,key);},`修改 ${row.address} 的邮箱密码需要重新认证。新密码只转成邮件认证哈希，不保存原文。`);
  }else if(action==='disable'||action==='enable'){
    const label=action==='disable'?'暂停':'恢复';
    openForm(`${label}邮箱账户`,freshFields(),async(v,key)=>{await fresh(v);return api(`/mailboxes/${row.id}/${action}`,'POST',{},key);},`对 ${row.address} 执行${label}需要重新输入管理员密码。`);
  }
}
function mailboxDeletePlan(row:Row){openForm('预览邮箱停用计划',freshFields(),async v=>{await fresh(v);const result=await api<Row>(`/mailboxes/${row.id}/delete-plan`,'POST');preview.value={plan:result};},`为 ${row.address} 生成停用计划需要重新认证。计划仅软删除，不会物理删除 Maildir；确认执行时还需再次重新认证并输入确认文字。`);}
function aliasForm(){openForm('新增别名 / 单目标转发',[selector('domainId','邮件域',domainOptions.value),{...text('address','别名完整地址'),type:'email'},{...text('destination','目标邮箱地址'),type:'email'},...freshFields()],async(v,key)=>{await fresh(v);return api('/aliases','POST',v,key);},'只允许真实启用邮箱或部署级已允许的外部域。不支持多目标群发及别名链。提交前需重新输入管理员密码。');}
function aliasRemove(row:Row){openForm('移除别名路由',[text('confirmation','输入要移除的完整别名地址'),...freshFields()],async(v,key)=>{if(v.confirmation!==row.address)throw new Error('确认地址不匹配');await fresh(v);return api(`/aliases/${row.id}`,'DELETE',undefined,key);},`将移除 ${row.address} → ${row.destination}。不会删除目标邮箱。此操作需要重新输入管理员密码。`);}
function attach(event:Event){attachments.value=Array.from((event.target as HTMLInputElement).files||[]);}
function encodeFile(file:File):Promise<string>{return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onerror=()=>reject(new Error('附件读取失败'));reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.readAsDataURL(file);});}
async function previewMail(){await perform(async()=>{if(attachments.value.length>2||attachments.value.some(file=>file.size>1048576))throw new Error('最多 2 个附件，每个最多 1 MiB。');const encoded=await Promise.all(attachments.value.map(async file=>({name:file.name,base64:await encodeFile(file)})));const result=await api<Row>('/mail/test-send','POST',{...mail.value,attachments:encoded});preview.value={plan:result};},'请核对邮件内容并确认收件人。');}
function observe(row:Row){openForm('记录人工投递观察',[selector('state','实际观察到的状态',[{value:'unconfirmed',label:'尚未确认'},{value:'inbox_seen',label:'在收件箱看到'},{value:'spam_seen',label:'在垃圾箱看到'},{value:'reply_received',label:'收到外部回信'}],row.recipient_confirmation)],v=>api(`/mail/sends/${row.id}/observation`,'POST',v),'这是管理员的人工记录，不是系统读取收件人邮箱的结果。');}
function settingsForm(){openForm('组织设置',[text('organization','组织名称',data.value.settings?.organization||''),text('timezone','时区',data.value.settings?.timezone||'Asia/Shanghai'),{...text('alertRecipient','计划告警收件人',data.value.settings?.alertRecipient||'',false),type:'email'}],v=>api('/settings','PUT',v),'本版本只有站内告警。填写地址不会启用尚未实现的邮件/Webhook 告警。网络目标、SMTP 密钥和备份位置只在部署文件中配置。');}
const roles=['Owner','MailAdmin','DnsAdmin','Operator','Auditor','WebsiteUserAdmin'].map(value=>({value,label:value}));
function adminForm(row?:Row){const fields:Field[]=row?[selector('role','角色',roles,row.role),{key:'active',label:'启用账号',type:'checkbox',value:row.active},text('confirmation',`输入 UPDATE ${row.id}`)]:[text('username','管理员用户名'),password(),selector('role','角色',roles)];openForm(row?'修改管理员权限':'新增管理员',[...fields,...freshFields()],async v=>{await fresh(v);return api(row?`/admins/${row.id}`:'/admins',row?'PUT':'POST',v);},'修改角色或停用会吊销相关会话。管理员使用自己的用户名和密码登录。');}
function reauthenticate(){openForm('重新认证',freshFields(),fresh,'高风险操作要求在最近 5 分钟内重新输入管理员密码，并在预览弹窗中确认。');}
async function copyRecords(){await perform(async()=>{await navigator.clipboard.writeText(dnsRecords.value.map(r=>`${r.name}\t${r.ttl}\tIN\t${r.type}\t${r.type==='MX'?`${r.priority} `:''}${r.content}`).join('\n'));},'DNS 记录已复制。');}
function exportAudit(){const blob=new Blob([JSON.stringify(rows.value,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download='astrogate-audit-current-page.json';anchor.click();URL.revokeObjectURL(url);notice.value='已导出当前页，不包含数据库中的全部审计历史。';}
const columns=computed(()=>{
  const sets:Partial<Record<Section,{key:string;label:string;status?:boolean;format?:(v:any)=>string}[]>>={
    nodes:[{key:'name',label:'节点'},{key:'instance_id',label:'安装实例'},{key:'status',label:'连接状态',status:true},{key:'readonly',label:'只读模式'},{key:'last_seen',label:'最近探测',format:time}],
    domains:[{key:'name',label:'邮件域'},{key:'mail_host',label:'邮件主机'},{key:'public_ipv4',label:'目标 IP'},{key:'registrar',label:'注册商'},{key:'provider',label:'DNS 托管方式',status:true}],
    mailboxes:[{key:'address',label:'邮箱账户'},{key:'state',label:'实际状态',status:true},{key:'quota_bytes',label:'配额',format:bytes},{key:'used_bytes',label:'使用量',format:bytes},{key:'last_login',label:'最近登录',format:time}],
    aliases:[{key:'address',label:'别名地址'},{key:'destination',label:'转发目标'},{key:'state',label:'状态',status:true}],
    sending:[{key:'sender',label:'发件人'},{key:'recipient',label:'收件人'},{key:'state',label:'SMTP 状态',status:true},{key:'recipient_confirmation',label:'人工观察',status:true},{key:'message_id',label:'Message-ID'}],
    queue:[{key:'queueId',label:'队列 ID'},{key:'queueName',label:'队列'},{key:'messageSize',label:'大小',format:bytes},{key:'arrivalTime',label:'入队时间'}],
    health:[{key:'name',label:'探测项'},{key:'state',label:'状态',status:true},{key:'source',label:'来源'},{key:'checked_at',label:'检查时间',format:time}],
    backups:[{key:'id',label:'备份 ID'},{key:'status',label:'状态',status:true},{key:'created_at',label:'创建时间',format:time}],
    tasks:[{key:'kind',label:'任务类型'},{key:'status',label:'状态',status:true},{key:'error_code',label:'错误代码'},{key:'attempts',label:'执行次数'},{key:'created_at',label:'提交时间',format:time}],
    audit:[{key:'actor',label:'操作人'},{key:'action',label:'动作'},{key:'outcome',label:'结果'},{key:'target',label:'对象'},{key:'created_at',label:'时间',format:time}],
    admins:[{key:'username',label:'管理员'},{key:'role',label:'角色'},{key:'active',label:'启用'},{key:'created_at',label:'创建时间',format:time}],
    sessions:[{key:'id',label:'会话 ID'},{key:'user_agent',label:'浏览器'},{key:'authenticated',label:'密码认证'},{key:'expires_at',label:'到期时间',format:time}]
  };return sets[section.value]||[];
});
</script>

<template>
  <AuthScreen v-if="!user" @ready="ready"/>
  <div v-else class="workspace">
    <aside :class="['sidebar',{expanded:mobileMenu}]"><a class="brand" href="#overview" @click.prevent="section=visibleNav[0].id"><span class="brand-mark">a<span>✦</span></span><span>Astrogate<small>MAIL ADMIN</small></span></a><div class="workspace-label">管理工作台 <span>SELF-HOSTED</span></div><nav aria-label="主导航"><button v-for="item in visibleNav" :key="item.id" :class="{selected:section===item.id}" :aria-current="section===item.id?'page':undefined" @click="section=item.id"><span aria-hidden="true">{{item.icon}}</span>{{item.label}}<i v-if="section===item.id"/></button></nav><div class="sidebar-footer"><span class="status-dot"/><div>工程交付版<small>0.1.0 · 未完成生产验收</small></div></div></aside>
    <div class="main-shell"><header class="topbar"><button class="mobile-toggle secondary" aria-label="切换导航" @click="mobileMenu=!mobileMenu">☰</button><div class="breadcrumb">工作台 <span>/</span> {{title}}</div><div class="user-controls"><button class="quiet" @click="reauthenticate">重新认证</button><span class="user-avatar">{{user.username?.slice(0,1).toUpperCase()}}</span><span class="user-name">{{user.username}}<small>{{user.role}}</small></span><button class="quiet" @click="logout">退出</button></div></header>
      <main class="content"><div class="page-heading"><div><small class="eyebrow">ASTROGATE CONTROL PLANE</small><h1>{{title}}</h1><p class="muted">{{section==='overview'?'从真实检查开始，掌握邮件服务的每一步。':'所有列表连接真实 API。未采集的数据明确显示为未知。'}}</p></div><div class="page-actions"><small v-if="lastRefresh" class="muted">更新于 {{lastRefresh}}</small><button class="secondary" :disabled="loading" @click="load">{{loading?'读取中…':'↻ 刷新'}}</button></div></div>
      <div class="release-strip"><span>尚未通过完整生产验收</span>请先在隔离环境完成构建、数据库初始化和现有邮件节点适配验证。<button class="quiet" @click="section='tasks'">查看任务 →</button></div>
      <p v-if="notice" class="notice success" role="status">{{notice}} <button class="quiet" aria-label="关闭通知" @click="notice=''">×</button></p><p v-if="problem" class="notice danger" role="alert">{{problem}}</p>
      <template v-if="section==='overview'"><div class="metrics"><button class="metric" @click="section='mailboxes'"><span>邮箱账户</span><strong>{{data.mailboxes??'—'}}</strong><small>独立邮件凭据 <b>↗</b></small></button><button class="metric" @click="section='domains'"><span>邮件域名</span><strong>{{data.domains??'—'}}</strong><small>期望状态与 DNS 检查 <b>↗</b></small></button><button class="metric" @click="section='tasks'"><span>待处理任务</span><strong>{{data.pendingTasks??'—'}}</strong><small>排队不等于成功 <b>↗</b></small></button><button class="metric" @click="section='tasks'"><span>24 小时失败 / 未知</span><strong>{{data.failedTasks??'—'}}</strong><small>需要人工核实 <b>↗</b></small></button></div><div class="dashboard-grid"><section class="panel"><div class="panel-title"><h2>邮件节点</h2><button v-if="may('Owner','MailAdmin','Operator','Auditor')" class="quiet" @click="section='nodes'">管理节点 →</button></div><DataTable :rows="data.nodes||[]" :columns="[{key:'name',label:'节点'},{key:'status',label:'连接',status:true},{key:'readonly',label:'只读'},{key:'stale',label:'探测已过期'}]" empty="尚未注册邮件节点。添加节点后，先进行只读扫描。"/></section><section class="panel delivery-note"><span class="outline-icon" aria-hidden="true">↗</span><h2>收到，不止是发出</h2><p>端口可连接、SMTP 接受、对方服务器接受、人工看到收件箱是不同状态。</p><span class="badge warn">收件箱 / 声誉：需外部人工观察</span><button v-if="may('Owner','MailAdmin','Auditor')" class="secondary" @click="section='sending'">查看测试投递</button></section></div><section class="panel"><div class="panel-title"><h2>最新探测</h2><button class="quiet" @click="section='health'">诊断详情 →</button></div><DataTable :rows="data.checks||[]" :columns="[{key:'name',label:'探测'},{key:'state',label:'结果',status:true},{key:'checked_at',label:'检查时间',format:time}]" empty="尚无检查结果，不显示虚假绿灯。"/></section></template>
      <template v-else-if="section==='website'"><section class="panel connector-state"><span class="outline-icon">♙</span><h2>网站用户目录尚未接入</h2><p>{{data.reason}}</p><p class="muted">网站用户、邮箱账户与后台管理员是三个独立实体。本版本不提供外部网站用户的冻结、重置或写入功能。</p><span class="badge neutral">连接器：disabled</span></section></template>
      <template v-else-if="section==='settings'"><section class="panel"><div class="panel-title"><h2>组织与部署设置</h2><button v-if="may('Owner')" @click="settingsForm">编辑组织设置</button></div><dl class="settings-list"><div><dt>组织</dt><dd>{{data.settings?.organization||'尚未设置'}}</dd></div><div><dt>时区</dt><dd>{{data.settings?.timezone||'尚未设置'}}</dd></div><div><dt>SMTP 连接</dt><dd>{{data.smtpConfigured?'部署文件已配置，尚需真实投递验收':'未配置'}}</dd></div><div><dt>允许的测试收件人</dt><dd>{{data.testRecipients?.join('、')||'未授权任何地址'}}</dd></div><div><dt>Agent 连接</dt><dd>{{data.agentConfigured?'部署文件已配置，请检查节点状态':'未配置'}}</dd></div><div><dt>备份范围</dt><dd>本机文件配置与显式源；不是完整灾备</dd></div><div><dt>告警</dt><dd>站内去重、静默和恢复状态；邮件 / Webhook 尚未实现</dd></div></dl></section></template>
      <template v-else>
        <section v-if="section==='sending'&&canMail" class="panel"><div class="panel-title"><h2>单封测试邮件</h2><span class="badge neutral">认证 · 收件人白名单 · 双重确认</span></div><form class="send-form" @submit.prevent="previewMail"><div class="form-grid"><label>发件人<input v-model="mail.from" type="email" autocomplete="off" required></label><label>明确的测试收件人<input v-model="mail.to" type="email" autocomplete="off" required></label><label class="wide">主题<input v-model="mail.subject" maxlength="200" required></label><label class="wide">正文<textarea v-model="mail.body" rows="6" maxlength="100000" required/></label><label class="checkbox-label"><input v-model="mail.html" type="checkbox"> HTML（服务端会移除不安全标记）</label><label>附件（最多 2 个，每个 1 MiB）<input type="file" accept=".txt,.pdf,.png,.jpg,.jpeg" multiple @change="attach"></label></div><div class="form-end"><small class="muted">每日每管理员最多 20 封，每目的地址每小时最多 3 封。</small><button type="submit" :disabled="loading">预览并确认发送 →</button></div></form></section>
        <section v-if="section==='backups'" class="notice warning">当前实现：本机显式备份源加密、完整性校验、隔离目录演练。未实现 S3、自动保留轮换及完整 PostgreSQL / Roundcube / 邮件服务恢复，不可当作唯一灾备。</section>
        <section v-if="section==='nodes'" class="notice">默认只读扫描。未知 mail-account 实现与不兼容 Dovecot 结构不会被自动接管。客户端清单显示 labMode 时，仅代表临时文件实验环境。</section>
        <section class="panel"><div class="toolbar"><div class="search-field"><span aria-hidden="true">⌕</span><input v-model="query" :aria-label="`搜索${title}当前页`" placeholder="搜索当前已加载记录…"></div><div class="toolbar-actions"><select v-if="['queue','health','backups'].includes(section)&&may('Owner','MailAdmin','Operator','Auditor')" v-model="nodeId" aria-label="选择邮件节点" @change="section==='queue'&&load()"><option value="" disabled>选择节点</option><option v-for="option in nodeOptions" :key="option.value" :value="option.value">{{option.label}}</option></select><button v-if="section==='nodes'&&may('Owner')" @click="newNode">＋ 注册节点</button><button v-if="section==='domains'&&canMail" @click="domainForm()">＋ 添加邮件域</button><button v-if="section==='mailboxes'&&canMail" @click="mailboxForm">＋ 创建邮箱</button><button v-if="section==='aliases'&&canMail" @click="aliasForm">＋ 新增别名</button><button v-if="section==='admins'" @click="adminForm()">＋ 新增管理员</button><button v-if="section==='backups'&&may('Owner','Operator')" :disabled="!nodeId" @click="perform(()=>api(`/backups?nodeId=${nodeId}`,'POST',undefined,idempotencyKey()))">创建加密备份</button><button v-if="section==='health'&&may('Owner','MailAdmin','Operator')" :disabled="!nodeId" @click="perform(()=>api(`/health/checks/run?nodeId=${nodeId}`,'POST',undefined,idempotencyKey()))">运行探测</button><button v-if="section==='audit'" class="secondary" @click="exportAudit">导出当前页</button></div></div>
        <DataTable :rows="filtered" :columns="columns"><template #actions="{row}"><template v-if="section==='nodes'"><button v-if="may('Owner','MailAdmin','Operator')" class="quiet" @click="perform(async()=>inspect(await api(`/nodes/${row.id}/scan`,'POST')),'只读扫描完成。')">扫描</button><button v-if="canMail" class="quiet" @click="perform(()=>api(`/nodes/${row.id}/import-mailboxes`,'POST'),'已导入账户元数据；节点未被修改。')">导入</button><button v-if="may('Owner')&&row.readonly" class="quiet" @click="plan(`/nodes/${row.id}/enable-management-plan`)">接管预览</button></template><template v-else-if="section==='domains'"><button class="quiet" @click="selectedDomain=row.id;desired()">DNS</button><button v-if="may('Owner','MailAdmin','DnsAdmin')" class="quiet" @click="domainForm(row)">编辑</button></template><template v-else-if="section==='mailboxes'&&canMail"><button class="quiet" :disabled="['pending','unknown','failed'].includes(row.state)" @click="mailboxAction(row,row.state==='active'?'disable':'enable')">{{row.state==='active'?'暂停':'恢复'}}</button><button class="quiet" @click="mailboxAction(row,'password-reset')">改密</button><button class="quiet" @click="mailboxAction(row,'quota')">配额</button><button class="quiet danger-text" @click="mailboxDeletePlan(row)">软删除</button></template><template v-else-if="section==='aliases'&&canMail"><button class="quiet danger-text" @click="aliasRemove(row)">移除</button></template><template v-else-if="section==='sending'&&canMail"><button class="quiet" @click="observe(row)">人工观察</button></template><template v-else-if="section==='queue'&&canMail"><button class="quiet" @click="perform(()=>api(`/mail/queue/${row.queueId}/retry?nodeId=${nodeId}`,'POST',undefined,idempotencyKey()))">请求重试</button><button class="quiet danger-text" @click="plan(`/mail/queue/${row.queueId}/delete-plan?nodeId=${nodeId}`)">删除预览</button></template><template v-else-if="section==='backups'"><button v-if="may('Owner','Operator')" class="quiet" @click="perform(()=>api(`/backups/${row.id}/verify`,'POST',undefined,idempotencyKey()))">完整性校验</button><button v-if="may('Owner')" class="quiet" :disabled="row.status!=='verified'" @click="plan(`/backups/${row.id}/restore-drill`)">隔离演练</button></template><template v-else-if="section==='admins'"><button class="quiet" @click="adminForm(row)">权限 / 停用</button></template><template v-else-if="section==='sessions'"><button class="quiet danger-text" @click="perform(()=>api(`/auth/sessions/${row.id}`,'DELETE'),'会话已吊销。')">吊销</button></template><button class="quiet" @click="inspect(row)">详情</button></template></DataTable><div class="table-footer">显示 {{filtered.length}} 条当前页记录<span>密码、密钥与邮件正文不会从账户列表返回</span></div></section>
        <section v-if="section==='domains'&&selectedDomain" class="panel"><div class="panel-title"><h2>期望 DNS 记录</h2><div class="toolbar-actions"><select v-model="selectedDomain" aria-label="选择 DNS 域名" @change="desired"><option v-for="domain in domains" :key="domain.id" :value="domain.id">{{domain.name}}</option></select><button class="secondary" @click="copyRecords">复制记录</button><button v-if="may('Owner','MailAdmin','DnsAdmin','Operator')" class="secondary" @click="perform(async()=>inspect(await api(`/domains/${selectedDomain}/dns/check`,'POST')),'DNS 查询完成。')">逐条检查</button><button v-if="canDns" class="secondary" @click="provider">配置 Provider</button><button v-if="canDns" @click="dnsPlan">变更预览</button></div></div><div class="notice">网站 A 记录不在邮件向导的修改范围。PTR / rDNS 由 IP 服务商维护；未填写 DKIM 公钥不会生成伪造的 DKIM 记录。</div><DataTable :rows="dnsRecords" :columns="[{key:'type',label:'类型'},{key:'name',label:'名称'},{key:'content',label:'期望内容'},{key:'priority',label:'优先级'},{key:'ttl',label:'TTL'}]"/><h3 class="subheading">DNS 变更计划</h3><DataTable :rows="dnsPlans" :columns="[{key:'id',label:'计划 ID'},{key:'state',label:'状态',status:true},{key:'expires_at',label:'确认到期',format:time}]"><template #actions="{row}"><button class="quiet" @click="inspect(row)">详情</button><button v-if="canDns&&row.state==='planned'" class="quiet" @click="perform(()=>confirmDns(row.id,'apply'),'请确认 DNS 影响范围。')">确认写入</button><button v-if="canDns&&row.state==='applied'" class="quiet" @click="perform(()=>confirmDns(row.id,'rollback'),'请确认 DNS 回滚影响范围。')">回滚预览</button></template></DataTable></section>
        <section v-if="section==='backups'" class="panel"><div class="panel-title"><h2>隔离演练报告</h2><span class="badge neutral">不覆盖源节点</span></div><DataTable :rows="drills" :columns="[{key:'id',label:'演练 ID'},{key:'state',label:'状态',status:true},{key:'created_at',label:'创建时间',format:time}]"><template #actions="{row}"><button class="quiet" @click="inspect(row.report)">查看报告与未验收项</button></template></DataTable></section>
        <section v-if="section==='health'" class="panel"><div class="panel-title"><h2>站内告警</h2><span class="badge neutral">去重 · 静默 · 恢复状态</span></div><DataTable :rows="data.alerts||[]" :columns="[{key:'message',label:'告警'},{key:'state',label:'状态',status:true},{key:'silenced_until',label:'静默至',format:time}]"><template #actions="{row}"><button v-if="may('Owner','Operator')" class="quiet" @click="perform(()=>api(`/alerts/${row.id}/silence`,'POST'),'告警已静默一小时。')">静默一小时</button></template></DataTable></section>
      </template>
      <section v-if="inspected!==null" class="panel details-panel"><div class="panel-title"><h2>详细结果</h2><button class="quiet" @click="inspected=null">关闭</button></div><pre class="json-preview">{{JSON.stringify(inspected,null,2)}}</pre></section>
      <footer class="page-footer"><span>Astrogate Mail Admin · MIT License</span><span>无默认密码 · 无匿名发信 · 默认只读接入</span></footer>
      </main>
    </div>
    <FormDialog v-if="form" :key="form.title" v-bind="form" @close="form=null"/>
    <PreviewDialog v-if="preview" :plan="preview.plan" :confirm="preview.confirm" :on-done="()=>{notice='操作已提交，请核对任务结果。';void load();}" @close="preview=null"/>
  </div>
</template>
