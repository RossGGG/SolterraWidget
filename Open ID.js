// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: deep-green; icon-glyph: user-circle;

let PREFS = {};

class ToybaruAuth {
    configuration = {
        realm: "https://login.subarudriverslogin.com/oauth2/realms/root/realms/tmna-native",
        client_id: "oneappsdkclient",
        scope: "openid profile write",
        redirect_uri: "com.toyota.oneapp:/oauth2Callback",
        cookie_name: "iPlanetDirectoryPro",
        sign_in_providers: {}
    }
    tokens = {}
    tokenId = null;
    auth_code = null;

    constructor(options= {}) {
        const {tokenId = null, auth_code = null, tokens = null, configuration = {}} = options;
        this.tokenId = tokenId;
        this.auth_code = auth_code;
        this.tokens = tokens;

        Object.assign(this.configuration, configuration);
    }

    // Discover OIDC configuration
    async discoverOIDCConfig(realm=null) {
        const url = `${realm || this.configuration.realm}/.well-known/openid-configuration`;

        const req = new Request(url);
        const config = await req.loadJSON();

        this.configuration.openid_config = config;

        return config;
    }

    async get_input(type) {
        let alert = new Alert()
        let message;
        if (type === "otp") {
            message = "Enter One Time Password for 2FA"
            alert.addTextField("000000", "").setNumberPadKeyboard()

        } else if (type === "login") {
            message = "Login with User Name and Password"
            alert.addTextField("User Name", "")
            alert.addSecureTextField("Password", "")
        }

        alert.message = message
        alert.title = "Subaru Solterra Connect"
        alert.addAction("OK")

        await alert.presentAlert()

        if (type === "login") {
            return {"username": alert.textFieldValue(0), "password": alert.textFieldValue(1)}
        }
        return alert.textFieldValue(0)
    }

    async process_auth_callbacks(data, creds= {}) {
        if ("callbacks" in data) {
            for (const callback of data["callbacks"]) {
                if (callback["type"] === "NameCallback") {
                    let input_type = callback["output"][0]["value"]

                    if (input_type === "ui_locales") {
                        callback["input"][0]["value"] = "en-US"

                    } else if (input_type === "User Name") {
                        creds = creds.hasOwnProperty("username") ? creds : await this.get_input("login")
                        callback["input"][0]["value"] = creds.username
                    }
                } else if (callback["type"] === "PasswordCallback") {
                    let input_type = callback["output"][0]["value"]

                    if (input_type === "One Time Password") {
                        callback["input"][0]["value"] = await this.get_input("otp")
                    } else {
                        creds = creds.hasOwnProperty("password") ? creds : await this.get_input("login")
                        callback["input"][0]["value"] = creds.password
                    }
                }
            }
        }
        return {data: data, creds: creds}
    }

    async authenticate_user(options = {}) {
        let {oid_config=null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        const headers = {
            "Accept-API-Version": "resource=2.1, protocol=1.0",
            "Content-Type": "application/json"
        }

        if (!oid_config.hasOwnProperty("authorization_endpoint")) {
            console.log(oid_config);
            return;
        }

        const authorizationUrl = `${options.oid_config.issuer.replace("oauth2", "json")}/authenticate`;

        let data = {
            "callbacks": [
                {
                    "type": "NameCallback",
                    "input": [{"name": "IDToken1", "value": "en-US"}],
                    "output": [{"name": "prompt", "value": "ui_locales"}]
                }
            ]
        };

        let req = new Request(authorizationUrl);
        req.method = "POST";
        req.headers = headers
        let token_cookie;
        let creds = {};

        for (const i of Array(10).keys()) {
            req.body = JSON.stringify(data);
            try {
                let json = await req.loadJSON()
                let processed = await this.process_auth_callbacks(json, creds);
                data = {...processed.data};
                if (Object.keys(processed.creds).length > 0) {
                    creds = processed.creds;
                }
            } catch (error){
                console.error(error);
                console.log(req);
            }

            if (!req.response || req.response.status_code > 400) {
                break;
            }

            token_cookie = req.response.cookies.find(cookie => cookie.name === "iPlanetDirectoryPro");
            if (token_cookie) {
                break;
            }
        }

        return token_cookie;
    }

    async acquire_authorization_code(options = {}) {
        let {auth_cookie = null, oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();


        // Initialize an authenticated user session with the OpenID server
        if (this.tokenId && !auth_cookie) {
            options.auth_cookie = {name: this.configuration.cookie_name, value: this.tokenId}
        } else {
            options.auth_cookie = auth_cookie || await this.authenticate_user(options);
        }
        const headers = {
            "Accept-API-Version": "resource=2.1, protocol=1.0",
            "Content-Type": "application/json",
            "Cookie": `${options.auth_cookie.name}=${options.auth_cookie.value}`
        }

        // Request an OpenID Authorization Code
        const params = {
            "client_id": this.configuration.client_id,
            "scope": this.configuration.scope,
            "response_type": "code",
            "redirect_uri": this.configuration.redirect_uri,
            "code_challenge": "plain",
            "code_challenge_method": "plain",
        }

        let params_url = this.Utilities.objectToQueryString(params);
        let auth_url = `${options.oid_config.authorization_endpoint}?${params_url}`;

        let req = new Request(auth_url);
        req.method = "GET";
        req.headers = headers;
        req.onRedirect = function (red) {
            return null
        }
        await req.load()

        // Parse authorization code from redirect uri
        if (!req.response.headers.hasOwnProperty("Location")) {
            console.error("No redirect url provided by server.")
            return
        }

        let redirect_query = this.Utilities.parseQueryParams(req.response.headers.Location);

        if (!redirect_query.hasOwnProperty("code")) {
            console.error("No authorization code provided by redirect url.");
            return
        }

        this.auth_code = redirect_query.code;

        return redirect_query.code;

    }

    async acquire_tokens(options = {}){
        let {authorization_code = null, oid_config = null} = options;

        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        // Use or retrieve Authorization Code
        if (this.auth_code && !authorization_code) {
            authorization_code = this.auth_code;
        } else {
            authorization_code = authorization_code || await this.acquire_authorization_code(options);
        }

        // Request tokens
        const params = {
            "client_id": this.configuration.client_id,
            "redirect_uri": this.configuration.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": "plain",
            "code": authorization_code,
        }

        let req = new Request(options.oid_config.token_endpoint);

        req.method = "POST";
        req.headers = {"Content-Type": "application/x-www-form-urlencoded"};
        req.body = this.Utilities.objectToQueryString(params);

        let tokens_payload = await req.loadJSON();
        this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options));
        return this.tokens;
    }

    async fetch_jwt_keys(options = {}){
        let {oid_config=null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        let req = new Request(options.oid_config.jwks_uri);

        req.method = "GET";

        let jwks = await req.loadJSON();

        return jwks;
    }

    async get_guid() {
        await this.check_tokens();
        if (this.tokens && this.tokens.guid) {
            return this.tokens.guid;
        } else {
            console.error("No GUID found.")
            console.error(JSON.stringify(this.tokens, undefined, 4));
        }
    }

    async get_access_token() {
        await this.check_tokens();
        if (this.tokens && this.tokens.access_token) {
            return this.tokens.access_token;
        } else {
            console.error("No access token found.")
            console.error(JSON.stringify(this.tokens, undefined, 4));
        }
    }

    async check_tokens() {
        if (this.tokens && this.tokens.hasOwnProperty("expires_at")) {
            if (Date.now() > this.tokens.expires_at) {
                return await this.refresh_tokens();
            }
        } else if (this.tokens === null) {
            console.error("No authroization tokens.  Please log in and try again.");
        }

        return this.tokens;
    }

    async refresh_tokens(options = {}){
        const {oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        if (!this.tokens.hasOwnProperty("refresh_token")) {
            return null
        }

        // Request tokens
        const params = {
            "client_id": this.configuration.client_id,
            "redirect_uri": this.configuration.redirect_uri,
            "grant_type": "refresh_token",
            "code_verifier": "plain",
            "refresh_token": this.tokens.refresh_token,
        }

        let req = new Request(options.oid_config.token_endpoint)
        req.method = "POST"
        req.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        req.body = Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');

        let tokens_payload = await req.loadJSON();
        if (tokens_payload.hasOwnProperty("error")) {
            console.error("Token Refresh Error");
            console.error(req.response);
            // console.log(params);
            this.tokens = null;
            this.auth_code = null;
            this.tokenId = null;
            return this.tokens;
        }

        this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options));
        return this.tokens;
    }

    Utilities = class {
        static objectToQueryString(params) {
            return Object.keys(params).map(key =>
                `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`
            ).join('&');
        }

        static parseQueryParams(url) {
            const params = {};
            // Extract the query string part of the URL
            const queryString = url.split('?')[1];
            if (!queryString) {
                return params; // return empty object if no query string exists
            }

            // Split the query string into key-value pairs
            queryString.split('&').forEach(param => {
                const [key, value] = param.split('=');
                // Decode URI components and add them to the params object
                params[decodeURIComponent(key)] = decodeURIComponent(value.replace(/\+/g, ' '));
            });

            return params;
        }

        static async extract_tokens(tokens, jwt_keys) {
            let new_tokens = {...tokens};
            const jwt = await this.parseJwt(tokens.id_token, jwt_keys);
            new_tokens.guid = jwt.sub;
            new_tokens.updated_at = Date.now();
            new_tokens.expires_at = tokens.updated_at + tokens.expires_in;

            //save_tokens(tokens)
            return new_tokens
        }

        static base64UrlDecode(str) {
            // Replace non-url compatible chars with base64 standard chars
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            // Pad out with standard base64 required padding characters
            const pad = str.length % 4;
            if (pad) {
                if (pad === 1) {
                    throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
                }
                str += new Array(5-pad).join('=');
            }
            return atob(str);
        }

        static key_to_PEM(key) {
            if (key.x5c && key.x5c.length > 0) {
                const pemPrefix = '-----BEGIN CERTIFICATE-----\n';
                const pemSuffix = '\n-----END CERTIFICATE-----';
                const base64Cert = key.x5c[0].replace(/(.{64})/g, '$1\n');
                return pemPrefix + base64Cert + pemSuffix;

            } else {
                console.error("Proper key entry or 'x5c' not found.");
            }
        }

        static async parseJwt(payload, jwks) {
            // console.log(JSON.stringify(jwks, undefined, 4))
            let jwt_payloads = payload.split(".");
            try {
                let data = {
                    headers: JSON.parse(this.base64UrlDecode(jwt_payloads[0])),
                    jwt: JSON.parse(this.base64UrlDecode(jwt_payloads[1])),
                    signature: jwt_payloads[2]
                }
                // console.log(JSON.stringify(data, undefined, 4))
                let key = this.key_to_PEM(jwks.keys.find(key => key.kid === data.headers.kid));

                let verified = false;
                try {
                    verified = this.verifyJWT(payload, key)
                } catch (e) {
                    if (e instanceof ReferenceError) {
                        verified = await this.executeInWebView({
                            func: this.verifyJWT,
                            context: this,
                            args: [payload, key],
                            remote_scripts: ["https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/11.1.0/jsrsasign-all-min.js"]
                        })
                        // console.log(`Verified? ${verified}`);
                    } else {
                        console.error("Unknown exception")
                        console.log(error.toString())
                    }
                }
                if (verified === true) {
                    return data.jwt;
                }

                console.error("Could not verify the integrity of the authenticated session tokens from the provided JWT.")

            } catch (error) {
                console.error(error)
                console.log(JSON.stringify(jwt_payloads, undefined, 4))
            }
        }

        static verifyJWT(token, publicKey) {
            try {
                // Instantiate RSAKey object with the public key
                const pubKey = KEYUTIL.getKey(publicKey);

                // Use jsrsasign to verify the token
                const isValid = KJUR.jws.JWS.verifyJWT(token, pubKey, {
                    alg: ['RS256'],
                    gracePeriod: 3600   // Optional: seconds of grace period for `nbf` and `exp` claims
                });

                // if (isValid) {
                //     console.log('JWT is valid');
                // } else {
                //     console.log('JWT is invalid');
                // }

                return isValid
            } catch (e) {
                if (e instanceof ReferenceError) {
                    throw e
                }
                console.error(`Error in verification: ${e.toString()}`);
            }
        }

        /**
         * Execute any function in a WebView.
         * @param {Object} options - Options for executing the function.
         * @param {Function} options.func - The function to execute.
         * @param {Array} [options.args=[]] - Arguments to pass to the function.
         * @param {Array} [options.remote_scripts=[]] - Remote scripts to load.
         * @returns {Promise<any>} - A promise that resolves with the result of the function execution.
         */
        static async executeInWebView(options) {
            const {func, context= null, args = [], remote_scripts = []} = options;
            // Create a new WebView
            let webView = new WebView();

            // Convert function and arguments into a string that can be executed in WebView
            let functionString = func.toString();
            if (!(functionString.startsWith("function") || functionString.startsWith("async function"))) {
                functionString = `function ${functionString}`;
            }
            const argsString = args.map(arg => JSON.stringify(arg)).join(',');
            const contextString = JSON.stringify(context);
            const remotesString = remote_scripts.map(script => `<script src="${script}"></script>`).join("\n");


            // Prepare a full HTML/JS content to execute the script
            const htmlContent = `
                <html>
                <head><title>Execute Script</title></head>
                <body>
                <input type="hidden" id="result" value="{}"/>
                ${remotesString}
                <script>
                    let consoleLogs = [];
                    const originalConsole = console; // Keep a reference to the original console
                    
                    // Override the console object
                    console = {
                        log(...args) {
                            consoleLogs.push({method: "log", arguments: args, timestamp: Date.now()});
                            originalConsole.log(...args); // Optional: maintain original log functionality
                        },
                        error(...args) {
                            consoleLogs.push({method: "error", arguments: args, timestamp: Date.now()});
                            originalConsole.error(...args); // Optional: maintain original error functionality
                        },
                        warn(...args) {
                            consoleLogs.push({method: "warn", arguments: args, timestamp: Date.now()});
                            originalConsole.warn(...args); // Optional
                        },
                        info(...args) {
                            consoleLogs.push({method: "info", arguments: args, timestamp: Date.now()});
                            originalConsole.info(...args); // Optional
                        },
                        debug(...args) {
                            consoleLogs.push({method: "debug", arguments: args, timestamp: Date.now()});
                            originalConsole.debug(...args); // Optional
                        }
                    };
        
                    async function executeFunction() {
                        let result;
                        try{
                            const src_func = (${functionString});
                            const context = ${contextString};
                            
                            let func = src_func;
                            if (context) {
                                func = src_func.bind(context);
                            }
                            
                            result = await func(${argsString});
                            document.getElementById('result').value = JSON.stringify({result: result});
                        } catch (error) {
                            document.getElementById('result').value = JSON.stringify({
                                error: error.message,
                                name: error.name,
                                stack: error.stack,
                                lineNumber: error.lineNumber, // Additional properties as needed
                                fileName: error.fileName,
                                logs: consoleLogs
                            });
                        }
                    }
                    
                    executeFunction().then(() => {
                        output = JSON.parse(document.getElementById('result').value)
                        output.logs = consoleLogs;
                        document.getElementById('result').value = JSON.stringify(output);
                    }).catch(error => {
                        document.getElementById('result').value = JSON.stringify({
                            error: error.message,
                            name: error.name,
                            stack: error.stack,
                            lineNumber: error.lineNumber, // Additional properties as needed
                            fileName: error.fileName,
                            logs: consoleLogs
                        });
                    });
                    
                    
                </script>
                </body>
                </html>
            `;

            // Load HTML content in the WebView
            await webView.loadHTML(htmlContent);

            // Evaluate the script and handle the output
            const resultJSON = await webView.evaluateJavaScript("document.getElementById('result').value");
            const resultObj = JSON.parse(resultJSON); // Parse the JSON string to an object

            // Helper function to format date
            function formatDate(date) {
                date = new Date(date);
                const pad = (num) => num.toString().padStart(2, '0');
                return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
                    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
            }

            // Process console logs
            if (resultObj.logs) {
                resultObj.logs.forEach(log => {
                    // Print log timestamp if not on same second as this print occurs
                    if (Math.floor(log.timestamp / 1000) * 1000 < Math.floor(Date.now() / 1000) * 1000) {
                        let first_arg = `\n${formatDate(log.timestamp)}: ${log.arguments.splice(0, 1).toString()}`
                        console[log.method](first_arg, ...log.arguments.splice(1, 0)); // Re-print logs in the main interpreter
                    } else console[log.method](...log.arguments); // Re-print logs in the main interpreter
                });
            }

            if (resultObj.error) {
                const error = new Error(resultObj.error);
                error.name = resultObj.name;
                error.stack = resultObj.stack;
                error.lineNumber = resultObj.lineNumber;
                error.fileName = resultObj.fileName;
                console.error(`Reconstructed Error: ${error}`);
                throw error;
                console.log()
            }

            return resultObj.result;
        }

    }
}

class ToybaruClient {
    configuration = {
        api_gateway: "https://oneapi1.telematicsct.com",
        apk: "TQCeSj6rOUOMVQB1V-O0QhuESDm-JUmuOAaeQDCla/JwJCa/akWOON::",
        cache_interval: 10000, //milliseconds
        refresh_interval: 60000, //milliseconds
    }
    auth = new ToybaruAuth();

    constructor(options={}) {
        if (options.auth) {
            this.auth = options.auth;
        }

        if (options.configuration) {
            Object.assign(this.configuration, options.configuration);
        }
    }

    async get_auth_headers() {
        let apk_name = atob("T@.?RBhqP-SW".split('').map(char => String.fromCharCode(char.charCodeAt(0) + 3)).join(''));
        let headers =
         {
            "AUTHORIZATION": `Bearer ${await this.auth.get_access_token()}`,
            "X-GUID": await this.auth.get_guid(),
            "X-APPBRAND": "S"
        }
        headers[apk_name] = atob(this.configuration.apk.split('').map(char => String.fromCharCode(char.charCodeAt(0) + 3)).join(''));
        return headers
    }

    async api_request(method, endpoint, header_params, json, ...args) {
        let req = new Request(`${this.configuration.api_gateway}/${endpoint}`);
        req.headers = await this.get_auth_headers();

        if (header_params != null) {
            req.headers = Object.assign({}, req.headers, header_params)
        }

        if (json != null) {
            req.headers = Object.assign({}, req.headers, {"Content-Type": "application/json"})
            req.body = JSON.stringify(json)
        }

        req.method = method

        let resp_json = await req.loadJSON()
        if (resp_json.hasOwnProperty("payload")) {
            return resp_json["payload"]
        } else {
            console.log(await req.loadString())

            if (resp_json.hasOwnProperty("status")) {
                if (resp_json["status"].hasOwnProperty("messages")) {
                    if (resp_json["status"]["messages"][0]["description"] == "Unauthorized") {
                        console.error("Client is not authorized.  Try logging in again.")
                    }
                }
            }
        }
        return null
    }

    async api_get(endpoint, header_params) {
        return await this.api_request("GET", endpoint, header_params)
    }

    async api_post(endpoint, json, header_params) {
        return await this.api_request("POST", endpoint, header_params, json)
    }

    async get_user_vehicle_list() {
        return await this.api_get("v3/vehicle/guid")
    }

    async get_vehicle(vin) {
        let vehicle = this.get_user_vehicle_list().find(vehicle => vehicle.vin === vin);

        return new ToybaruClientVehicle(this, vehicle);
    }
}

class ToybaruClientVehicle {
    vehicle_data = {
        vin: "",
        nickName: "",
        displayModelDescription: "",
        image: "",
    }
    client = new ToybaruClient();
    status_cache = {};
    last_ev_timestamp = null;
    last_status_timestamp = null;
    next_refresh;

    constructor(client, vehicle_data) {
        this.client = client;
        this.vehicle_data = {...vehicle_data};
    }

    async verify_vin() {
        let vins = await this.client.get_user_vehicle_list.map(function (vehicle) {
            return vehicle.vin;
        })
        return this.vehicle_data.vin in vins;


    }

    async remote_request(command) {
        let result = await this.client.api_post("v1/global/remote/command", {"command": command}, {"VIN": this.vehicle_data.vin});
        if (result["returnCode"] == "000000") {
            return true;
        }
        return false;
    }

    async refresh_request() {
        let result_electric = await this.client.api_post("v2/electric/realtime-status", {"guid": await this.client.auth.get_guid(), "vin": this.vehicle_data.vin}, {"VIN": this.vehicle_data.vin});
        let result = await this.client.api_post("v1/global/remote/refresh-status", {"guid": await this.client.auth.get_guid(), "vin": this.vehicle_data.vin}, {"VIN": this.vehicle_data.vin});

        if (result.returnCode === "000000" && result_electric.returnCode === "000000") {
            return true;
        }
        return false;
    }

    async remote_door_lock() {
        return await this.client.remote_request(this.vehicle_data.vin, "door-lock");
    }

    async remote_door_unlock() {
        return await this.client.remote_request(this.vehicle_data.vin, "door-unlock");
    }

    async remote_engine_start() {
        return await this.client.remote_request(this.vehicle_data.vin, "engine-start");
    }

    async remote_engine_stop() {
        return await this.client.remote_request(this.vehicle_data.vin, "engine-stop");
    }

    async get_vehicle_status() {
        let status;

        if (this.status_cache.last_status && (Date.now() - this.status_cache.last_status.cached_at > this.client.configuration.cache_interval)) {
            status = this.status_cache.last_status;
        } else {
            status = await this.client.api_get("v1/global/remote/status", {"VIN": this.vehicle_data.vin});
            this.status_cache.last_status = ev_status;
            this.status_cache.last_status.cached_at = Date.now();
        }
        if (status.occurrenceDate) {
            this.last_status_timestamp = new Date(status.occurrenceDate);

            let now = new Date();
            if ((now - this.last_status_timestamp )> this.client.configuration.refresh_interval){
                await this.refresh_request();
            }
        }
        return status
    }

    async get_electric_status() {
        let ev_status;
        if (this.status_cache.last_ev_status && (Date.now() - this.status_cache.last_ev_status.cached_at > this.client.configuration.cache_interval)) {
            ev_status = this.status_cache.last_status;
        } else {
            ev_status = await this.client.api_get("v2/electric/status", {"VIN": this.vehicle_data.vin})
            this.status_cache.last_ev_status = ev_status;
            this.status_cache.last_ev_status.cached_at = Date.now();
        }

        if (ev_status.vehicleInfo && ev_status.vehicleInfo.acquisitionDatetime) {
            this.last_ev_timestamp = new Date(ev_status.vehicleInfo.acquisitionDatetime);

            // Request updated status from vehicle if data is stale.
            let now = Date.now();
            if ((now - this.last_ev_timestamp )> this.client.configuration.refresh_interval){
                await this.refresh_request();
                // Allow the widget to refresh again after 20 seconds.
                this.next_refresh = Date.now() + 20000;
            } else {
                // Prevent widget from refreshing before the refresh interval.
                this.next_refresh = Date.now() + this.client.configuration.refresh_interval;
            }
        }
        return ev_status;
    }

    async get_charge_info(property) {
        let ev_status = await this.get_electric_status();

        if (ev_status.vehicleInfo && ev_status.vehicleInfo.chargeInfo) {
            if (property === null) {
                return ev_status.vehicleInfo.chargeInfo;

            } else if (ev_status.vehicleInfo.chargeInfo.hasOwnProperty(property)) {
                return ev_status.vehicleInfo.chargeInfo[property];
            }
        }

    }

    async get_car_image() {
        return this.vehicle_data.image;
    }

    async get_battery_percentage(vin) {
        return await this.get_charge_info("chargeRemainingAmount");
    }

    async get_ev_distances() {
        let chargeInfo = await this.get_charge_info();
        if (chargeInfo != null) {
            return {
                evDistance: chargeInfo.evDistance,
                evDistanceAC: chargeInfo.evDistanceAC,
                unit: chargeInfo.evDistanceUnit
            };
        }
    }

    async get_charge_time() {
        let chargeInfo = await this.get_charge_info();
        if (chargeInfo != null) {
            return chargeInfo.remainingChargeTime;
        }
    }

    async get_lock_status() {
        let vehicle_status = await this.get_vehicle_status();

        if (vehicle_status === null) {
            return vehicle_status;
        }

        let locked = true;

        for (let category of vehicle_status.vehicleStatus) {
            for (let section of category.sections) {
                for (let value of section.values) {
                    if (value.value === "Unlocked") {
                        locked = false;
                    }
                }
            }
        }

        return locked;
    }

    async is_locked() {
        let locked = await this.get_lock_status();

        return locked
    }
}

class ToybaruApp {

    _prefs = {};

    constructor(options = {}) {
        const {auth = new ToybaruAuth({tokenId: options.tokenId}), client = null, vehicle = null} = options;

        this.load_prefs();
        if (client) {
            this.client = client
        } else if (vehicle) {
            this.client = vehicle.client;
        } else {
            this.client = new ToybaruClient({auth: auth});
        }

        if (this._prefs.vehicle && !vehicle) {
            this.vehicle = new ToybaruClientVehicle(this.client, this._prefs.vehicle);
        } else {
            this.vehicle = vehicle || null;
        }
    }

    async init() {
        if (this.client.auth.tokenId) {
            await this.client.auth.acquire_tokens();
            this.save_tokens();
        } else {
            await this.load_tokens()
        }

        if (!this.client.auth.tokens) {
            await this.login();
        }

        if (!this.vehicle) {
            await this.select_vehicle();
        }
    }

    async load_tokens() {
        let tokens = {}
        if (Keychain.contains("subaru_tokens")) {
            tokens = JSON.parse(Keychain.get("subaru_tokens"))
            this.client.auth.tokens = tokens;
            await this.client.auth.check_tokens();
            this.save_tokens();
        }
    }

    save_tokens() {
        Keychain.set("subaru_tokens", JSON.stringify(this.client.auth.tokens))
    }

    save_prefs() {
        Keychain.set("subaru_connect_prefs", JSON.stringify(this._prefs));
    }

    load_prefs() {
        if (Keychain.contains("subaru_connect_prefs")) {
            this._prefs = JSON.parse(Keychain.get("subaru_connect_prefs"));
        }
    }

    async login() {
        let fm = FileManager.iCloud();
        let path = fm.joinPath(fm.documentsDirectory(), "ToybaruLogin.html")
        let url = `file://${path}?success=${URLScheme.forRunningScript()}`

        let wv = new WebView();
        wv.shouldAllowRequest = request => {
            if (!request.url.startsWith(URLScheme.forRunningScript())) return true;
            // HERE - Close the WebView
            webview.loadHTML('Please close this window');
            return false;
        }

        await wv.loadHTML(url);
        wv.present();
    }

    async select_vehicle() {
        let selected_vehicle = {}
        const vehicles = await this.client.get_user_vehicle_list();

        // Create a table
        let table = new UITable()

        // Create a header row
        let headerRow = new UITableRow()
        headerRow.isHeader = true
        headerRow.addText("Select Vehicle")
        table.addRow(headerRow)

        // Create a row for each animal
        for (let vehicle of vehicles) {
            let row = new UITableRow();
            const image = row.addImageAtURL(vehicle.image);
            image.widthWeight = 15;
            row.height = 100;
            const text = row.addText(vehicle.nickName, vehicle.displayModelDescription);
            text.leftAligned();
            text.widthWeight = 80;
            row.onSelect = () => {
                selected_vehicle = vehicle;
            }
            table.addRow(row);
        }

        // Present the table
        await table.present()

        this._prefs.vehicle = selected_vehicle;
        save_prefs();

        this.vehicle = new ToybaruClientVehicle(this.client, selected_vehicle);
        return this.vehicle;
    }
}

async function main(options = {}) {
    let tba = new ToybaruApp({tokenId: options.tokenId})
    await tba.init();

    console.log(await tba.vehicle.get_electric_status());

}

await main(args.queryParameters);
