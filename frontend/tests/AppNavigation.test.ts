import {afterEach,describe,expect,it,vi} from 'vitest';
import {flushPromises,mount} from '@vue/test-utils';
import {defineComponent,h,onMounted} from 'vue';

vi.mock('../src/api',()=>({
  ApiFailure:class ApiFailure extends Error{},
  api:vi.fn(),
  idempotencyKey:()=> 'test-key'
}));

import {api} from '../src/api';
import App from '../src/App.vue';

afterEach(()=>vi.clearAllMocks());

describe('sidebar navigation',()=>{
  it('renders role-filtered groups, expands the active group, and selects a child page',async()=>{
    vi.mocked(api).mockImplementation(async(path:string)=>path==='/overview'?{checks:[],nodes:[]}:[] as never);
    const AuthStub=defineComponent({
      emits:['ready'],
      setup(_,context){onMounted(()=>context.emit('ready',{username:'admin',role:'Owner'}));return()=>h('div');}
    });
    const wrapper=mount(App,{global:{stubs:{AuthScreen:AuthStub,DataTable:true,FormDialog:true,PreviewDialog:true}}});
    await flushPromises();

    expect(wrapper.find('[aria-label="主导航"]').text()).toContain('邮箱管理');
    expect(wrapper.text()).toContain('投递与节点');
    expect(wrapper.get('button[aria-current="page"]').text()).toContain('系统概览');

    const workspaceToggle=wrapper.findAll('.nav-group__toggle').find(button=>button.text().includes('工作台'))!;
    await workspaceToggle.trigger('click');
    expect(wrapper.find('#nav-items-workspace').exists()).toBe(false);
    const mailToggle=wrapper.findAll('.nav-group__toggle').find(button=>button.text().includes('邮箱管理'))!;
    expect(mailToggle.attributes('aria-expanded')).toBe('true');
    await mailToggle.trigger('click');
    expect(wrapper.find('#nav-items-mail').exists()).toBe(false);
    await mailToggle.trigger('click');
    const mailboxPage=wrapper.findAll('.nav-item').find(button=>button.text().includes('邮箱账户'))!;
    await mailboxPage.trigger('click');
    await flushPromises();
    expect(mailboxPage.attributes('aria-current')).toBe('page');
    expect(api).toHaveBeenCalledWith('/mailboxes');
    expect(wrapper.find('.nav-group__toggle.has-current').text()).toContain('邮箱管理');
  });
});
