const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('Solterra Connect.js', 'utf8');
const html = fs.readFileSync('SolterraConnectApp.html', 'utf8');
function setup(responses) {
 const requests = [];
 class Request {
  constructor(url) { this.url = url; requests.push(this); }
  async loadJSON() { const r = responses.shift(); this.response = {statusCode: r.status ?? 200, cookies: r.cookies ?? []}; return r.body; }
 }
 const context = vm.createContext({Request, DebugLogger: {log(){}, error(){}}, LoginError: class LoginError extends Error {name='LoginError'}, NotLoggedInError: Error});
 vm.runInContext(source.slice(source.indexOf('class ToybaruAuth'), source.indexOf('class ToybaruClient')) + '\nglobalThis.Auth = ToybaruAuth;', context);
 return {auth: new context.Auth(), requests};
}
const oid = {issuer: 'https://login.subarudriverslogin.com/oauth2/realms/root/realms/tmna-native', authorization_endpoint: 'https://auth/authorize', token_endpoint: 'https://auth/token'};
test('OTP callback loop retains node affinity and accepts tokenId without a session cookie', async () => {
 const {auth, requests} = setup([{body:{callbacks:[{type:'ConfirmationCallback', input:[{value:1}]}]}, cookies:[{name:'amlbcookie', value:'node1'}]}, {body:{tokenId:'session'}}]);
 const cookie = await auth.authenticate_user({oid_config:oid});
 assert.equal(cookie.value, 'session');
 assert.equal(requests[0].headers.Cookie, 'amlbcookie=node1');
 assert.equal(JSON.parse(requests[0].body).callbacks[0].input[0].value, 0);
});
test('refresh rejection differs from temporary server failure', async () => {
 for (const [status, body, expected] of [[400,{error:'invalid_grant'},'LoginError'],[503,{},'Error']]) {
  const {auth, requests} = setup([{status,body}]);
  auth.tokens = {refresh_token:'fake'};
  auth.Utils.unpack_jwt = () => ({jwt:{exp:0}});
  await assert.rejects(auth.refresh_tokens({oid_config:oid}), {name:expected});
  assert.match(requests[0].body, /redirect_uri=/);
  assert.equal(auth.tokens.refresh_token, 'fake');
 }
});
test('temporary refresh failure propagates and preserves saved credentials', async () => {
 const {auth} = setup([]);
 auth.tokens = {expires_at:0, refresh_token:'saved'};
 auth.refresh_tokens = async () => {throw new Error('unavailable')};
 await assert.rejects(auth.check_tokens(), /unavailable/);
 assert.equal(auth.tokens.refresh_token, 'saved');
});
test('embedded app equals editable HTML and both scripts parse', () => {
 assert.equal(Buffer.from(source.match(/const WebApp = Data.fromBase64String\('([^']+)'/)[1], 'base64').toString(), html);
 new vm.Script('(async function(){'+source+'\n})');
 for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) if (!match[0].includes('text/babel')) new vm.Script(match[1]);
});
