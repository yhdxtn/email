import {describe,it,expect} from 'vitest';
import {mount} from '@vue/test-utils';
import DataTable from '../src/components/DataTable.vue';
describe('API result table',()=>{
  it('renders an honest empty state',()=>{const wrapper=mount(DataTable,{props:{rows:[],columns:[{key:'state',label:'状态'}]}});expect(wrapper.text()).toContain('暂无记录');expect(wrapper.find('tbody tr').exists()).toBe(false);});
  it('escapes hostile content without executing HTML',()=>{const wrapper=mount(DataTable,{props:{rows:[{id:'one',name:'<img src=x onerror=alert(1)>'}],columns:[{key:'name',label:'名称'}]}});expect(wrapper.find('img').exists()).toBe(false);expect(wrapper.text()).toContain('<img');});
  it('labels queued as queued, not completed',()=>{const wrapper=mount(DataTable,{props:{rows:[{id:'one',state:'queued'}],columns:[{key:'state',label:'状态',status:true}]}});expect(wrapper.text()).toContain('已排队');expect(wrapper.text()).not.toContain('已完成');});
});
