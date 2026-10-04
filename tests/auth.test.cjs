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
  async loadString() { return JSON.stringify(await this.loadJSON()); }
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

test('Babel 6 webapp contains no nullish or optional chaining syntax', () => {
 const babelScript = html.match(/<script type="text\/babel">([\s\S]*?)<\/script>/)[1];
 const withoutComments = babelScript.replace(/\/\/[^\n]*/g, '');
 assert.doesNotMatch(withoutComments, /\?\?|\?\./);
});

test('native web auth uses a restricted endpoint allowlist and keeps affinity cookies', async () => {
 const {auth, requests} = setup([
  {body: {callbacks: []}, cookies: [{name: 'amlbcookie', value: 'node1'}]},
  {body: {tokenId: 'session'}}
 ]);
 const url = auth.configuration.realm.replace('oauth2', 'json') + '/authenticate';
 await auth.web_auth_request({url, method: 'POST', body: '{}'});
 const result = await auth.web_auth_request({url, method: 'POST', body: '{}'});
 assert.equal(requests[1].headers.Cookie, 'amlbcookie=node1');
 assert.equal(JSON.parse(result.body).tokenId, 'session');
 await assert.rejects(auth.web_auth_request({url: 'https://example.com', method: 'GET'}), /Unsupported/);
 assert.equal(requests.length, 2);
});

test('clearing tokens without an existing key is safe', () => {
 const method = source.match(/    save_tokens\(tokens = null\) \{([\s\S]*?)\n    save_prefs/)[1];
 const context = vm.createContext({Keychain: {contains: () => false, remove: () => {throw new Error('missing key')}}});
 vm.runInContext('function save_tokens(tokens = null) {' + method + '\nsave_tokens();', context);
});

function webLogin(authenticate_user) {
 const method = html.slice(html.indexOf('        check_login() {'), html.indexOf('        updateRefreshState(state) {'));
 const context = vm.createContext({navigator:{userAgent:'iPhone AppleWebKit'}, ScriptableRequest:{login(){}}, Object});
 vm.runInContext('class App {' + method + '} globalThis.App = App;', context);
 const app = new context.App();
 Object.assign(app, {nativeSessionReady:false, loginPending:false, authGeneration:0, user:{}, main:{getElementsByClassName:()=>[]}, auth:{authenticate_user}, handle_auth_callbacks(){}, showToast(){app.toasts++}, toasts:0});
 return app;
}
test('startup waits for native session, and never authenticates an existing user', () => {
 let calls = 0;
 const app = webLogin(() => {calls++; return Promise.resolve()});
 assert.equal(app.check_login(), false);
 app.nativeSessionReady = true;
 app.user = {name:'test'};
 assert.equal(app.check_login(), true);
 assert.equal(calls, 0);
});
test('login is single-flight and a superseded failure cannot show a warning', async () => {
 let reject, calls = 0;
 const app = webLogin(() => {calls++; return new Promise((_, r) => {reject = r})});
 app.nativeSessionReady = true;
 app.check_login(); app.check_login();
 assert.equal(calls, 1);
 app.user = {name:'test'}; app.authGeneration++;
 reject(new Error('load failed'));
 await new Promise(resolve => setImmediate(resolve));
 assert.equal(app.toasts, 0);
});
test('current login failures still show a useful warning', async () => {
 const app = webLogin(() => Promise.reject(new Error('offline')));
 app.nativeSessionReady = true;
 app.check_login();
 await new Promise(resolve => setImmediate(resolve));
 assert.equal(app.toasts, 1);
 assert.equal(app.loginPending, false);
});
function chargingVehicle(readings, response = {appRequestNo:'request/1'}) {
 const calls = [];
 const client = {get_device_id:()=> 'device', api_post:async (endpoint, options)=>{calls.push({endpoint, options});return response}, api_get:async endpoint=>{calls.push({endpoint});return readings.shift()}};
 const context = vm.createContext({ToybaruClient:class {}, Date, encodeURIComponent});
 vm.runInContext(source.slice(source.indexOf('class ToybaruClientVehicle'), source.indexOf('class ToybaruApp')) + '\nglobalThis.Vehicle = ToybaruClientVehicle;', context);
 const cached = {vehicleInfo:{acquisitionDatetime:'2026-10-04T01:00:00Z', battery:59},cached_at:0};
 return {vehicle:new context.Vehicle(client,{vin:'DEMO',status_cache:{last_ev_status:cached}}), calls, cached};
}
test('charging refresh correlates request, ignores old readings, and publishes a newer reading', async () => {
 const fresh = {vehicleInfo:{acquisitionDatetime:'2026-10-04T01:01:00Z',battery:60}};
 const {vehicle,calls,cached} = chargingVehicle([{vehicleInfo:cachedInfo()}, fresh]);
 let updates = 0;
 const state = await vehicle.refresh_charging_status({wait:async()=>{},onUpdate:async()=>{updates++}});
 assert.equal(state,'updated'); assert.equal(updates,1);
 assert.equal(vehicle.status_cache.last_ev_status.vehicleInfo.battery,60);
 assert.equal(JSON.stringify(calls[0].options.json),'{}');
 assert.equal(calls[0].options.header['device-id'],'device');
 assert.match(calls[1].endpoint,/realtime-status=request%2F1/);
 assert.notEqual(vehicle.status_cache.last_ev_status,cached);
});
function cachedInfo() {return {acquisitionDatetime:'2026-10-04T01:00:00Z',battery:59}}
test('unchanged charging reading times out without destroying cache', async () => {
 const {vehicle,calls,cached} = chargingVehicle([{vehicleInfo:cachedInfo()},{vehicleInfo:cachedInfo()}]);
 assert.equal(await vehicle.refresh_charging_status({wait:async()=>{},attempts:2}),'timeout');
 assert.equal(vehicle.status_cache.last_ev_status,cached);
 assert.equal(calls.length,3);
});
test('rejected charging request and failed poll preserve cached data', async () => {
 for (const response of [{returnCode:'rejected'},{appRequestNo:'id'}]) {
  const {vehicle,cached} = chargingVehicle([undefined],response);
  await assert.rejects(vehicle.refresh_charging_status({wait:async()=>{}}));
  assert.equal(vehicle.status_cache.last_ev_status,cached);
 }
});
test('pending refresh renders cache immediately without another network request', async () => {
 const {vehicle,calls,cached} = chargingVehicle([]);
 vehicle.charging_refresh_pending = true;
 assert.equal(await vehicle.get_electric_status(),cached);
 assert.equal(calls.length,0);
});
test('pending correlated replies keep polling until the new reading is ready', async () => {
 const {vehicle} = chargingVehicle([{}, {vehicleInfo:{acquisitionDatetime:'2026-10-04T01:01:00Z'}}]);
 assert.equal(await vehicle.refresh_charging_status({wait:async()=>{}}),'updated');
});
test('refresh UI shows a spinner and disables duplicate requests, then allows retry', () => {
 const method = html.slice(html.indexOf('        updateRefreshState(state) {'), html.indexOf('        update_container_visibilities() {'));
 const elements = {charging_refresh_message:{},charging_refresh_spinner:{},charging_refresh_button:{}};
 const context = vm.createContext({document:{getElementById:id=>elements[id]}});
 vm.runInContext('class App {'+method+'} globalThis.app = new App();',context);
 context.app.updateRefreshState('pending');
 assert.equal(elements.charging_refresh_spinner.hidden,false);
 assert.equal(elements.charging_refresh_button.disabled,true);
 assert.match(elements.charging_refresh_message.textContent,/last available/);
 for (const state of ['updated','timeout','error']) {
  context.app.updateRefreshState(state);
  assert.equal(elements.charging_refresh_spinner.hidden,true);
  assert.equal(elements.charging_refresh_button.disabled,false);
  assert.ok(elements.charging_refresh_message.textContent.length);
 }
});
