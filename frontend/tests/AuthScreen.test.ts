import {afterEach,describe,expect,it,vi} from 'vitest';
import {flushPromises,mount} from '@vue/test-utils';

vi.mock('../src/api',()=>({
  ApiFailure:class ApiFailure extends Error{constructor(public code:string,message:string,public status:number){super(message);}},
  api:vi.fn(),
  refreshCsrf:vi.fn()
}));

import {api,ApiFailure,refreshCsrf} from '../src/api';
import AuthScreen from '../src/components/AuthScreen.vue';

afterEach(()=>vi.clearAllMocks());

describe('Admin authentication availability states',()=>{
  it('shows login only when the backend confirms there is no active session',async()=>{
    vi.mocked(refreshCsrf).mockResolvedValue(undefined);
    vi.mocked(api).mockResolvedValueOnce({needsSetup:false}).mockRejectedValueOnce(new ApiFailure('AUTH_REQUIRED','请先登录',401));
    const wrapper=mount(AuthScreen);await flushPromises();
    expect(wrapper.find('input[autocomplete="username"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('登录管理控制台');
  });

  it('hides credentials on service failure and offers a retry',async()=>{
    vi.mocked(refreshCsrf).mockResolvedValue(undefined);
    vi.mocked(api).mockRejectedValueOnce(new ApiFailure('BACKEND_UNAVAILABLE','暂时无法连接后台',503));
    const wrapper=mount(AuthScreen);await flushPromises();
    expect(wrapper.find('input[autocomplete="username"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('暂时无法连接后台');
    vi.mocked(api).mockResolvedValueOnce({needsSetup:false}).mockRejectedValueOnce(new ApiFailure('AUTH_REQUIRED','请先登录',401));
    await wrapper.get('button[type="button"]').trigger('click');await flushPromises();
    expect(wrapper.find('input[autocomplete="username"]').exists()).toBe(true);
  });
});
