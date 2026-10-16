<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, reactive, ref } from 'vue';
import type { Field, Row } from '../types';
const props=defineProps<{title:string;description?:string;fields:Field[];submitLabel?:string;submit:(values:Row)=>Promise<void>}>();
const emit=defineEmits<{close:[]}>();
const values=reactive<Row>({});for(const field of props.fields)values[field.key]=field.value??(field.type==='checkbox'?false:'');
const pending=ref(false),error=ref(''),element=ref<HTMLDialogElement>();
const previouslyFocused=document.activeElement as HTMLElement|null;
onMounted(async()=>{await nextTick();element.value?.showModal();});
onUnmounted(()=>previouslyFocused?.focus());
function close(){if(!pending.value)emit('close');}
async function save(){
  pending.value=true;error.value='';
  try{const body={...values};for(const field of props.fields)if(field.type==='number')body[field.key]=Number(body[field.key]);await props.submit(body);for(const field of props.fields)if(field.type==='password')values[field.key]='';emit('close');}
  catch(e){error.value=e instanceof Error?e.message:'操作失败';}
  finally{pending.value=false;}
}
</script>
<template><dialog ref="element" class="modal" aria-labelledby="form-title" @cancel.prevent="close"><form @submit.prevent="save"><div class="dialog-heading"><div><small>ASTROGATE / 操作</small><h2 id="form-title">{{title}}</h2></div><button type="button" class="icon-button" aria-label="关闭" :disabled="pending" @click="close">×</button></div><p v-if="description" class="muted">{{description}}</p><div class="form-grid"><label v-for="field in fields" :key="field.key" :class="{wide:field.type==='textarea'}"><span>{{field.label}}<em v-if="field.required"> *</em></span><textarea v-if="field.type==='textarea'" v-model="values[field.key]" :required="field.required" rows="4" :maxlength="field.max||100000"/><select v-else-if="field.type==='select'" v-model="values[field.key]" :required="field.required"><option value="" disabled>请选择</option><option v-for="option in field.options" :key="option.value" :value="option.value">{{option.label}}</option></select><input v-else v-model="values[field.key]" :type="field.type||'text'" :required="field.required" :min="field.type==='number'?field.min:undefined" :max="field.type==='number'?field.max:undefined" :minlength="field.type!=='number'?field.min:undefined" :maxlength="field.type!=='number'?field.max:undefined" :autocomplete="field.type==='password'?'new-password':'off'" :spellcheck="false"><small v-if="field.hint">{{field.hint}}</small></label></div><p v-if="error" class="notice danger" role="alert">{{error}}</p><footer class="dialog-footer"><button type="button" class="secondary" :disabled="pending" @click="close">取消</button><button type="submit" :disabled="pending">{{pending?'正在提交…':submitLabel||'保存'}}</button></footer></form></dialog></template>
