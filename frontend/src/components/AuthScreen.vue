<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, ApiFailure, refreshCsrf } from '../api';
import type { Row } from '../types';

const emit=defineEmits<{ready:[user:Row]}>();
const stage=ref<'loading'|'unavailable'|'setup'|'login'>('loading');
const username=ref(''),password=ref(''),token=ref(''),busy=ref(false),error=ref('');

async function initialize(){
  busy.value=true;error.value='';stage.value='loading';
  try{
    await refreshCsrf();
    const setup=await api<Row>('/setup/status');
    if(setup.needsSetup){stage.value='setup';return;}
    try{emit('ready',await api<Row>('/auth/me'));}
    catch(e){if(e instanceof ApiFailure&&e.status===401&&e.code==='AUTH_REQUIRED'){stage.value='login';return;}throw e;}
  }catch(e){error.value=e instanceof Error?e.message:'后端不可用';stage.value='unavailable';}
  finally{busy.value=false;}
}

onMounted(()=>{void initialize();});

async function submit(){
  busy.value=true;error.value='';
  try{
    if(stage.value==='setup'){
      await api('/setup/initialize','POST',{username:username.value,password:password.value,token:token.value});
      token.value='';stage.value='login';
    }else if(stage.value==='login'){
      await api('/auth/login','POST',{username:username.value,password:password.value});
      emit('ready',await api<Row>('/auth/me'));
    }
  }catch(e){error.value=e instanceof Error?e.message:'认证失败';}
  finally{password.value='';busy.value=false;}
}
</script>

<template>
  <main class="auth-shell">
    <section class="auth-brand">
      <div class="brand-symbol" aria-hidden="true">a<span>✦</span></div>
      <small>ASTROGATE / MAIL ADMIN</small>
      <h1>你的邮件服务。<br>清晰、可控。</h1>
      <p>账户、域名与节点，在同一个控制台中管理。<br>保留现有系统，从只读检查开始。</p>
      <div class="auth-footnote">SELF-HOSTED CONTROL PLANE · 0.1.0</div>
    </section>
    <section class="auth-form">
      <div class="notice warning">工程交付版 · 尚未通过完整生产验收</div>
      <small class="eyebrow">安全访问</small>
      <h2>{{stage==='setup'?'初始化管理员':stage==='unavailable'?'服务暂不可用':stage==='loading'?'正在检查服务状态':'登录管理控制台'}}</h2>
      <p class="muted">{{stage==='setup'?'初始化仅允许执行一次。令牌位于部署机 secrets/setup-token 文件。':stage==='unavailable'?'暂时无法读取管理后台状态。确认服务运行后重试；连接恢复前不会显示凭据表单。':stage==='loading'?'正在检查管理后台…':'请输入后台管理员用户名和密码。登录成功后直接进入控制台。'}}</p>
      <form v-if="stage!=='unavailable'&&stage!=='loading'" @submit.prevent="submit">
        <label v-if="stage==='setup'">一次性初始化令牌<input v-model="token" type="password" required autocomplete="off"></label>
        <label>管理员用户名<input v-model="username" required autocomplete="username" minlength="3" maxlength="64" pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}"></label>
        <label>管理员密码<input v-model="password" type="password" required :minlength="stage==='setup'?9:undefined" maxlength="72" :autocomplete="stage==='setup'?'new-password':'current-password'"></label>
        <p v-if="error" role="alert" class="notice danger">{{error}}</p>
        <button class="full-width" type="submit" :disabled="busy">{{busy?'正在验证…':stage==='setup'?'创建唯一初始管理员':'登录并进入'}}</button>
      </form>
      <p v-if="stage==='unavailable'" role="alert" class="notice danger">{{error}}</p>
      <button v-if="stage==='unavailable'" type="button" class="full-width" :disabled="busy" @click="initialize">{{busy?'检查中…':'重新检查连接'}}</button>
      <a class="auth-mail-link" href="https://mail.astrogate.sbs/" target="_blank" rel="noopener noreferrer">普通邮箱用户登录 →</a>
      <p class="auth-note">使用管理后台账号，不是邮箱账户密码。<br>连接失败时不会切换到演示数据。</p>
    </section>
  </main>
</template>
