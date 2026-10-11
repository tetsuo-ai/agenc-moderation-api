import { expect, it } from 'vitest';
import { isPublicAddress } from '../src/ssrf-fetch.js';
it.each(['fec0::1','feff::1','2001:0:1234::1','2002:0808:0808::1'])('refuses additional IPv6 SSRF range: %s',ip=>expect(isPublicAddress(ip,6)).toBe(false));
it.each(['192.88.99.0','192.88.99.255'])('refuses deprecated IPv4 relay: %s',ip=>expect(isPublicAddress(ip,4)).toBe(false));
it('still permits public addresses',()=>{expect(isPublicAddress('8.8.8.8',4)).toBe(true);expect(isPublicAddress('2606:4700:4700::1111',6)).toBe(true);});
