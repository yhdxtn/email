<script setup lang="ts">
import { display, label, tone } from '../format';
import type { Row } from '../types';
withDefaults(defineProps<{rows:Row[];columns:{key:string;label:string;status?:boolean;format?:(value:any)=>string}[];empty?:string}>(),{empty:'暂无记录。此处仅显示后端返回的数据。'});
</script>
<template>
  <div v-if="rows.length" class="table-scroll"><table><thead><tr><th v-for="column in columns" :key="column.key" scope="col">{{column.label}}</th><th v-if="$slots.actions" scope="col">操作</th></tr></thead><tbody><tr v-for="(row,index) in rows" :key="row.id||row.address||index"><td v-for="column in columns" :key="column.key"><span v-if="column.status" :class="['badge',tone(row[column.key])]">{{label(row[column.key])}}</span><span v-else class="cell-text">{{column.format?column.format(row[column.key]):display(row[column.key])}}</span></td><td v-if="$slots.actions"><div class="row-actions"><slot name="actions" :row="row"/></div></td></tr></tbody></table></div>
  <div v-else class="empty"><span class="empty-glyph" aria-hidden="true">◇</span><p>{{empty}}</p></div>
</template>
