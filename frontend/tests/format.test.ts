import {describe,it,expect} from 'vitest';
import {label,tone,bytes,display,time} from '../src/format';
describe('Truthful state presentation',()=>{
  it('does not equate SMTP acceptance to inbox delivery',()=>expect(label('smtp_accepted')).toBe('SMTP 已接受'));
  it('leaves missing counters unknown',()=>expect(bytes(null)).toBe('未采集'));
  it('distinguishes unknown from healthy',()=>expect(tone('unknown')).toBe('warn'));
  it('formats exact IEC units',()=>expect(bytes(1073741824)).toBe('1.0 GiB'));
  it('invalid date is not now',()=>expect(time('not-a-date')).toBe('未知'));
  it('missing timestamp is not success',()=>expect(time(null)).toBe('未记录'));
  it('renders JSON as text',()=>expect(display({body:'<script>'})).toContain('<script>'));
});
