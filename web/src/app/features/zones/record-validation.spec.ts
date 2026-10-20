import { isIpv4, isIpv6, validateName, validateRecord } from './record-validation';

const ok = (type: string, value: string, name = 'www', ttl = '') =>
  validateRecord({ name, type, ttl, value });

describe('record validation', () => {
  it('record_form_validates_type_value', () => {
    expect(ok('A', '192.0.2.1')).toEqual({});
    expect(ok('A', '192.0.2.256').value).toBeDefined();
    expect(ok('A', '2001:db8::1').value).toBeDefined();
    expect(ok('AAAA', '2001:db8::1')).toEqual({});
    expect(ok('AAAA', '192.0.2.1').value).toBeDefined();
    expect(ok('CNAME', 'target.example.com.')).toEqual({});
    expect(ok('CNAME', 'bad host').value).toBeDefined();
    expect(ok('NS', 'ns1.example.com.')).toEqual({});
    expect(ok('PTR', '@').value).toBeDefined();
    expect(ok('MX', '10 mail.example.com.')).toEqual({});
    expect(ok('MX', 'mail.example.com.').value).toBeDefined();
    expect(ok('MX', '70000 mail.example.com.').value).toBeDefined();
    expect(ok('TXT', '"v=spf1 -all"')).toEqual({});
    expect(ok('TXT', 'x'.repeat(4097)).value).toBeDefined();
    expect(ok('SRV', '10 5 5060 sip.example.com.')).toEqual({});
    expect(ok('SRV', '10 5 sip.example.com.').value).toBeDefined();
    expect(ok('CAA', '0 issue "letsencrypt.org"')).toEqual({});
    expect(ok('CAA', '300 issue "x"').value).toBeDefined();
    expect(ok('CAA', '0 issue').value).toBeDefined();
    expect(ok('A', '').value).toBe('Required.');
    expect(ok('SPF', 'x').type).toBeDefined();
  });

  it('validates_ttl', () => {
    expect(ok('A', '192.0.2.1', 'www', '300')).toEqual({});
    expect(ok('A', '192.0.2.1', 'www', '0')).toEqual({});
    expect(ok('A', '192.0.2.1', 'www', '-1').ttl).toBeDefined();
    expect(ok('A', '192.0.2.1', 'www', '1.5').ttl).toBeDefined();
    expect(ok('A', '192.0.2.1', 'www', '2147483648').ttl).toBeDefined();
  });

  it('validates_names', () => {
    expect(validateName('@', true)).toBeNull();
    expect(validateName('@', false)).not.toBeNull();
    expect(validateName('', true)).toBe('Required.');
    expect(validateName('*.example.com.', true)).toBeNull();
    expect(validateName('_dmarc', true)).toBeNull();
    expect(validateName('a..b', true)).toBe('Empty label.');
    expect(validateName('-bad', true)).toContain('Invalid label');
    expect(validateName('a'.repeat(64), true)).toContain('63');
    expect(validateName(`${'a'.repeat(60)}.`.repeat(5), true)).toContain('253');
    expect(validateName('.', true)).toBeNull();
    expect(validateName('.', false)).not.toBeNull();
  });

  it('parses_ip_literals', () => {
    expect(isIpv4('1.2.3')).toBe(false);
    expect(isIpv4('01.2.3.4')).toBe(false);
    expect(isIpv6('::')).toBe(true);
    expect(isIpv6('::1')).toBe(true);
    expect(isIpv6('1:2:3:4:5:6:7:8')).toBe(true);
    expect(isIpv6('1:2:3:4:5:6:7')).toBe(false);
    expect(isIpv6('1::2::3')).toBe(false);
    expect(isIpv6('::ffff:192.0.2.1')).toBe(true);
    expect(isIpv6('::ffff:999.0.2.1')).toBe(false);
    expect(isIpv6('1:2:3:4:5:6:7:8::')).toBe(false);
    expect(isIpv6('g::1')).toBe(false);
    expect(isIpv6(':::')).toBe(false);
  });
});
