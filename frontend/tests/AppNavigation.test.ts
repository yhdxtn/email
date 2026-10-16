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

function authStub(role:string){return defineComponent({
  emits:['ready'],
  setup(_,context){onMounted(()=>context.emit('ready',{username:'admin',role}));return()=>h('div');}
});}

describe('sidebar navigation',()=>{
  it('renders grouped navigation, allows collapsing groups, and selects a child page',async()=>{
    vi.mocked(api).mockImplementation(async(path:string)=>path==='/overview'?{checks:[],nodes:[]}:[] as never);
    const wrapper=mount(App,{global:{stubs:{AuthScreen:authStub('Owner'),DataTable:true,FormDialog:true,PreviewDialog:true}}});
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

  it('hides pages outside the signed-in administrator role',async()=>{
    vi.mocked(api).mockImplementation(async(path:string)=>path==='/overview'?{checks:[],nodes:[]}:[] as never);
    const wrapper=mount(App,{global:{stubs:{AuthScreen:authStub('MailAdmin'),DataTable:true,FormDialog:true,PreviewDialog:true}}});
    await flushPromises();

    const pages=wrapper.findAll('.nav-item').map(button=>button.text());
    expect(pages.some(page=>page.includes('邮箱账户'))).toBe(true);
    expect(pages.some(page=>page.includes('测试邮件'))).toBe(true);
    expect(pages.some(page=>page.includes('管理员权限'))).toBe(false);
    expect(pages.some(page=>page.includes('网站用户'))).toBe(false);
  });
});
