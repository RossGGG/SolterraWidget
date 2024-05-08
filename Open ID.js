// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: deep-green; icon-glyph: user-circle;

class LoginError extends Error {
    constructor(message) {
        super(message); // Pass the message to the Error constructor
        this.name = 'LoginError'; // Set the name of the error
    }
}

class NotLoggedInError extends Error {
    constructor(message) {
        super(message); // Pass the message to the Error constructor
        this.name = 'NotLoggedInError'; // Set the name of the error
    }
}

class ExpiredTokenError extends Error {
    constructor(message) {
        super(message); // Pass the message to the Error constructor
        this.name = 'ExpiredTokenError'; // Set the name of the error
    }
}

class ToybaruAuth {
    configuration = {
        realm: "https://login.subarudriverslogin.com/oauth2/realms/root/realms/tmna-native",
        client_id: "oneappsdkclient",
        scope: "openid profile write",
        redirect_uri: "com.toyota.oneapp:/oauth2Callback",
        cookie_name: "iPlanetDirectoryPro",
        sign_in_providers: {}
    }

    callback;
    tokens = {}
    tokenId = null;
    auth_code = null;
    refresh_secs;

    constructor(options = {}) {
        const {
            callback = null,
            tokenId = null,
            auth_code = null,
            tokens = null,
            configuration = {},
            refresh_secs = 300} = options;

        this.callback = callback;
        this.tokenId = tokenId;
        this.auth_code = auth_code;
        this.tokens = tokens;
        this.refresh_secs = refresh_secs;

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
            console.error("No Authorization Endpoint found in OpenID Configuration.");
            console.error(oid_config);
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

        if (req.response.statusCode !== 200) {
            throw new LoginError("Error acquiring tokens.");
        }

        tokens_payload.auth_code = authorization_code;

        this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options), this.callback);

        return this.tokens;
    }

    async fetch_jwt_keys(options = {}){
        let {oid_config=null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        let req = new Request(options.oid_config.jwks_uri);

        req.method = "GET";

        return await req.loadJSON();
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
            if (this.tokens.expires_at < Date.now()) {
                try {
                    console.log("Token has expired. Refreshing tokens.");
                    return await this.refresh_tokens();
                } catch (error) {
                    console.error(error);
                    if (error.name === "LoginError") {
                        console.log(this.tokenId);
                        if (this.tokenId) {
                            try {
                                return await this.acquire_tokens();
                            } catch (error) {
                                if (error.name === "LoginError") {
                                    console.log("Error acquiring tokens using saved session.")
                                }
                            }
                        }

                        // Clear tokens and auth code
                        this.tokens = null;
                        this.auth_code = null;

                        if (this.callback) {
                            console.log("Clearing saved tokens.")
                            await this.callback(this.tokens);
                        }

                        throw new ExpiredTokenError("Token has expired.");
                    }
                }

            } else if (this.refresh_secs > 0 && Date.now() > this.tokens.updated_at + this.refresh_secs * 1000) {
                return await this.refresh_tokens();

            } else if (this.refresh_secs < 0 && Date.now() > this.tokens.expires_at + this.refresh_secs * 1000) {
                return await this.refresh_tokens();

            } else if (this.refresh_secs === 0) {
                return await this.refresh_tokens();
            }

        } else {
            throw new NotLoggedInError("User is not logged in.");
        }

        return this.tokens;
    }

    get is_logged_in() {
        return this.tokens !== null && this.tokens.hasOwnProperty("access_token") && this.tokens.hasOwnProperty("refresh_token") && this.tokens.hasOwnProperty("id_token");
    }

    async refresh_tokens(options = {}){
        const {oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        if (!this.tokens.hasOwnProperty("refresh_token")) {
            throw new NotLoggedInError("No refresh token found.")
        }

        // Request tokens
        const params = {
            "client_id": this.configuration.client_id,
            "code_verifier": "plain",
            "grant_type": "refresh_token",
            "redirect_uri": this.configuration.redirect_uri,
            "refresh_token": this.tokens.refresh_token,
        }

        let req = new Request(options.oid_config.token_endpoint)
        req.method = "POST"
        req.headers = {"Content-Type": "application/x-www-form-urlencoded"};
        req.body = this.Utilities.objectToQueryString(params);

        let tokens_payload = await req.loadJSON();
        if (req.response.statusCode !== 200) {
            console.error("Error refreshing tokens.")
            console.error(JSON.stringify(tokens_payload, undefined, 4));
            throw new LoginError("Refresh token has expired.");

        } else {
            this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options), this.callback);
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

        static async extract_tokens(tokens, jwt_keys, callback=null) {
            let new_tokens = {...tokens};
            const jwt = await this.parseJwt(tokens.id_token, jwt_keys);
            new_tokens.guid = jwt.sub;
            new_tokens.updated_at = Date.now();
            new_tokens.expires_at = new_tokens.updated_at + new_tokens.expires_in * 1000;

            if (callback) {
                await callback(new_tokens);
            }

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

                // Verify the JWT token

                return KJUR.jws.JWS.verifyJWT(token, pubKey, {
                    alg: ['RS256'],
                    gracePeriod: 3600   // Optional: seconds of grace period for `nbf` and `exp` claims
                })
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
            }

            return resultObj.result;
        }

    }
}

class ToybaruClient {
    configuration = {
        api_gateway: "https://oneapi.telematicsct.com",
        apk: "TQCeSj6rOUOMVQB1V-O0QhuESDm-JUmuOAaeQDCla/JwJCa/akWOON::",
        cache_interval: 10000, //milliseconds
        refresh_interval: 300000, //milliseconds
    }
    auth;
    device_id;

    constructor(options = {}) {
        const {auth = new ToybaruAuth({callback: options.callback}), device_id = null} = options;

        this.auth = auth;

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

    get_device_id() {
        if (!this.device_id) {
            this.device_id = this.Utilities.generateNewDeviceId();
        }

        return this.device_id;
    }

    Utilities = class {
        static generateRandomBigInt(hexDigits) {
            let hexString = '';
            for(let i = 0; i < hexDigits; i++) {
                hexString += Math.floor(Math.random() * 16).toString(16);
            }
            return BigInt('0x' + hexString);
        }

        static generateNewDeviceId() {
            // Generate a random BigInt for the device ID
            let deviceId = this.generateRandomBigInt(64);

            // Convert the BigInt to a hexadecimal string and pad it with zeros
            let hexDeviceId = deviceId.toString(16).padStart(64, '0');

            return hexDeviceId;
        }
    }

    async api_request({method, endpoint, header = {}, json = null}) {
        if (this.auth.is_logged_in) {
            let req = new Request(`${this.configuration.api_gateway}/${endpoint}`);
            req.headers = {...await this.get_auth_headers(), ...header};

            if (json) {
                req.headers = {"Content-Type": "application/json", ...req.headers};
                req.body = JSON.stringify(json, undefined, 4);
            }

            req.method = method;
            try {
                let resp_json = await req.loadJSON();
                if (resp_json.payload) {
                    return resp_json.payload;
                } else if (resp_json.status?.messages?.[0]?.description === "Unauthorized") {
                    console.error("Client is not authorized. Try logging in again.");
                }
            } catch (error) {
                console.error(error);
                console.log(req.response);
            }

            return req.response;
        }
    }

    async api_get(endpoint, options= {}) {
        return await this.api_request({method: "GET", endpoint: endpoint, ...options});
    }

    async api_post(endpoint, options = {}) {
        return await this.api_request({method: "POST", endpoint: endpoint, ...options});
    }

    async get_user_vehicle_list() {
        return await this.api_get("v3/vehicle/guid");
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

    next_refresh;

    constructor(client, vehicle_data) {
        let {status_cache, ...remaining_data} = vehicle_data;
        this.client = client;
        this.status_cache = status_cache || {};
        this.vehicle_data = {...remaining_data};
    }

    get last_ev_timestamp() {
        if (this.status_cache.last_ev_status && this.status_cache.last_ev_status.vehicleInfo && this.status_cache.last_ev_status.vehicleInfo.acquisitionDatetime) {
            return new Date(this.status_cache.last_ev_status.vehicleInfo.acquisitionDatetime);
        }
        return null
    }

    get last_status_timestamp() {
        if (this.status_cache.last_status && this.status_cache.last_status.occurrenceDate) {
            return new Date(this.status_cache.last_status.occurrenceDate);
        }
        return null
    }

    async verify_vin() {
        let vins = await this.client.get_user_vehicle_list.map(function (vehicle) {
            return vehicle.vin;
        })
        return this.vehicle_data.vin in vins;


    }

    async remote_request(command) {
        let result = await this.client.api_post("v1/global/remote/command", {json: {"command": command}, header: {"VIN": this.vehicle_data.vin}});
        return result.returnCode === "000000";

    }

    async refresh_status_request() {
        let result = await this.client.api_post("v1/global/remote/refresh-status", {
            json: {
                guid: await this.client.auth.get_guid(),
                deviceId: this.client.get_device_id(),
                vin: this.vehicle_data.vin
            }, header: {VIN: this.vehicle_data.vin}
        });
        try {
            return result.returnCode && result.returnCode === "000000";
        } catch {
            console.error("Error refreshing vehicle status.")
            console.error(result)
            return false;
        }
    }

    async refresh_ev_status_request() {
        let result_electric = await this.client.api_post("v2/electric/realtime-status", {
            json: {
                guid: await this.client.auth.get_guid(),
                deviceId: this.client.get_device_id(),
                vin: this.vehicle_data.vin
            }, header: {VIN: this.vehicle_data.vin}
        });
        try {
            return result_electric.returnCode && result_electric.returnCode === "000000";
        } catch {
            console.error("Error refreshing EV status.");
            console.error(result_electric);
        }
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

        if (this.status_cache.last_status && (Date.now() - this.status_cache.last_status.cached_at < this.client.configuration.cache_interval)) {
            status = this.status_cache.last_status;
        } else {
            status = await this.client.api_get("v1/global/remote/status", {header: {"VIN": this.vehicle_data.vin}});
            this.status_cache.last_status = status;
            this.status_cache.last_status.cached_at = Date.now();
        }
        if (status.occurrenceDate) {
            let now = new Date();
            if ((now - this.last_status_timestamp )> this.client.configuration.refresh_interval){
                await this.refresh_status_request();

                // Allow the widget to refresh again after 20 seconds.
                this.next_refresh = Date.now() + 20000;
            } else {
                // Prevent widget from refreshing before the refresh interval.
                this.next_refresh = Date.now() + this.client.configuration.refresh_interval;
            }
        }
        return status
    }

    async get_electric_status() {
        let ev_status;
        if (this.status_cache.last_ev_status && (Date.now() - this.status_cache.last_ev_status.cached_at < this.client.configuration.cache_interval)) {
            ev_status = this.status_cache.last_ev_status;
        } else {
            ev_status = await this.client.api_get("v2/electric/status", {header: {"VIN": this.vehicle_data.vin}})
            this.status_cache.last_ev_status = ev_status;
            this.status_cache.last_ev_status.cached_at = Date.now();
        }

        if (ev_status.vehicleInfo && ev_status.vehicleInfo.acquisitionDatetime) {
            // Request updated status from vehicle if data is stale.
            let now = Date.now();
            if ((now - this.last_ev_timestamp )> this.client.configuration.refresh_interval){
                await this.refresh_ev_status_request();
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
    client;
    vehicle;

    constructor(options = {}) {
        const {auth = new ToybaruAuth({tokenId: options.tokenId, callback: this.save_tokens}), client = null, vehicle = null} = options;

        if (client) {
            this.client = client
        } else if (vehicle) {
            this.client = vehicle.client;
        } else {
            this.client = new ToybaruClient({auth: auth, callback: this.save_tokens});
        }
        this.load_prefs();

        if (this._prefs.vehicle && !vehicle) {
            this.vehicle = new ToybaruClientVehicle(this.client, this._prefs.vehicle);
        } else {
            this.vehicle = vehicle || null;
        }
    }

    async init() {
        if (this.client.auth.tokenId) {
            await this.client.auth.acquire_tokens();

        } else {
            try {
                await this.load_tokens()
            } catch (error) {
                console.error(error);
                if (["NotLoggedInError", "ExpiredTokenError"].includes(error.name)) {
                    console.error("User is not logged in.");
                }
            }

            if (config.runsInApp && !this.client.auth.is_logged_in) {
                await this.login();
            }
        }

        if (!this.vehicle) {
            await this.select_vehicle();
        }

        this.save_prefs();
    }

    async load_tokens() {
        let tokens = {}
        if (Keychain.contains("subaru_tokens")) {
            tokens = JSON.parse(Keychain.get("subaru_tokens"))
            this.client.auth.tokens = tokens;

            if (tokens.auth_code) {
                this.client.auth.auth_code = tokens.auth_code;
            }

            await this.client.auth.check_tokens();
        }
    }

    save_tokens(tokens=null) {
        if (!tokens) {
            Keychain.remove("subaru_tokens");
            return
        }

        Keychain.set("subaru_tokens", JSON.stringify(tokens))
    }

    save_prefs() {
        this._prefs.device_id = this.client.get_device_id();
        this._prefs.vehicle.status_cache = this.vehicle.status_cache;

        Keychain.set("subaru_connect_prefs", JSON.stringify(this._prefs));
    }

    load_prefs() {
        if (Keychain.contains("subaru_connect_prefs")) {
            this._prefs = JSON.parse(Keychain.get("subaru_connect_prefs"));
            this.client.device_id = this._prefs.device_id ? this._prefs.device_id : this.client.get_device_id();
        }
    }

    async login() {
        let fm = FileManager.iCloud();
        let path = fm.joinPath(fm.documentsDirectory(), "ToybaruLogin.html")
        let url = `file://${path}?locale=${Device.locale().replace("_", "-")}&success=${URLScheme.forRunningScript()}`

        let wv = new WebView();
        wv.shouldAllowRequest = request => {
            if (!request.url.startsWith(URLScheme.forRunningScript())) return true;
            // HERE - Close the WebView
            webview.loadHTML('Please close this window');
            return false;
        }

        await wv.loadURL(url);
        await wv.present();
    }

    get is_logged_in() {
        return this.client.auth.is_logged_in;
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
        this.save_prefs();

        this.vehicle = new ToybaruClientVehicle(this.client, selected_vehicle);
        return this.vehicle;
    }
}

async function createAccessoryWidget(options){// Create Widget
    let widget = new ListWidget();
    stack = widget.addStack();
    image = await draw_meter(options);
    console.log(image);
    stack.addImage(image);
    return widget
}

async function get_vehicle_widget_values(vehicle) {
    const vehicle_status = await vehicle.get_vehicle_status();
    const ev_status = await vehicle.get_electric_status();

    const check_values = (category_name, section_name, value_name, compare_to) => {
        return vehicle_status.vehicleStatus.some(category => category.category.includes(category_name) && category.sections.some(section => section.section === section_name && section.values.some(value => value.value.includes(value_name) && value.status === compare_to)))
    }

    return {
        value: ev_status.vehicleInfo.chargeInfo.chargeRemainingAmount,
        charging: ![12, 45].includes(ev_status.vehicleInfo.chargeInfo.plugStatus),
        plugged_in: ev_status.vehicleInfo.chargeInfo.connectorStatus > 2,
        door_open: check_values("Side", "Door", "Closed", 1) &&
            check_values("Side", "Rear Door", "Closed", 1),
        door_unlocked: check_values("Side", "Door", "Unlocked", 1) &&
            check_values("Side", "Rear Door", "Unlocked", 1),
        liftgate_open: check_values("Other", "Hatch", "Closed", 1),
        window_f_open: check_values("Side", "Window", "Closed", 1),
        window_r_open: check_values("Side", "Rear Window", "Closed", 1),
    }
}

async function draw_meter(options={}) {

    // JavaScript code to create a canvas, draw something, and then convert it to a base64 image
    // Create a new WebView instance
    let wv = new WebView();

    // HTML content with inline JavaScript using Path2D to draw an arc
    let htmlContent = `
        <html>
        <head>
        </head>
        <body>
        <canvas id="canvas" width="300" height="300"></canvas>
        <script>
            function draw(
              options = {}
            ) {
              default_options = { scale: 275,
                        start: 0.15,
                        end: 0.85,
                        weight: 25,
                        fg_color: "white",
                        bg_color: "black",
                        glyph_color: null,
                        label: true,
                        show_car_status: true,
                        charging: false,
                        plugged_in: false,
                        door_open: false,
                        door_unlocked: false,
                        liftgate_open: false,
                        window_f_open: false,
                        window_r_open: false
                      }
              options = {...default_options, ...options};

              var canvas = document.getElementById('canvas');

              
              let origin = { x: options.scale / 2, y: options.scale / 2 };
              let scale_factor = options.scale / 225;
              canvas.width = options.scale;
              canvas.height = options.scale;
              
              let start_pos = options.start;
              let end_pos = options.end;

              if (options.label) {
                  // Adjust Car Icon position to below meter
                  car_pos = {x: origin.x - 60 * scale_factor, y: origin.y + 55*scale_factor};
                  car_scale = {x: 0.2 * scale_factor, y: 0.2 * scale_factor};
                  

              } else {
                // Adjust meter to be full circle
                start_pos = 0.5;
                end_pos = 1.5;

                // Adjust Car Icon position to center inside meter
                car_pos = {x: origin.x - 65 * scale_factor, y: origin.y - 30*scale_factor}
                car_scale = {x: 0.2 * scale_factor, y: 0.2 * scale_factor}
              }

              if (canvas.getContext) {
                var ctx = canvas.getContext('2d');
                let radius = options.scale / 2.2;
                let weight = options.weight;
                rounded_arc(ctx, origin, radius, weight, start_pos, end_pos);
                ctx.fillStyle = options.bg_color;
                ctx.fill();
            
                ctx.fillStyle = options.fg_color;
                ctx.strokeStyle = options.fg_color;

                if (options.value) {
                    rounded_arc(
                      ctx,
                      origin,
                      radius + 1,
                      weight + 2,
                      start_pos,
                      start_pos + (end_pos - start_pos) * (options.value / 100)
                    );
                    
                    ctx.fill();
                }
                
                let glyph_color = options.glyph_color || options.fg_color;
                
                let label_origin = {x: origin.x, y: origin.y};
                
                // Draw Lock Status Icon
                if (options.door_unlocked) {
                    label_origin.y += 25*scale_factor;
                    let lock = new Path2D("M2.19727 19.1406L11.1328 19.1406C12.5684 19.1406 13.3301 18.3594 13.3301 16.8164L13.3301 10.0879C13.3301 8.55469 12.5684 7.77344 11.1328 7.77344L2.19727 7.77344C0.761719 7.77344 0 8.55469 0 10.0879L0 16.8164C0 18.3594 0.761719 19.1406 2.19727 19.1406ZM10.1855 8.53516L11.7285 8.53516L11.7285 5.24414C11.7285 2.77344 13.3105 1.47461 15.1367 1.47461C16.9629 1.47461 18.5449 2.77344 18.5449 5.24414L18.5449 7.41211C18.5449 7.98828 18.8867 8.28125 19.3262 8.28125C19.7461 8.28125 20.0977 8.01758 20.0977 7.41211L20.0977 5.44922C20.0977 1.77734 17.6855 0 15.1367 0C12.5781 0 10.1855 1.77734 10.1855 5.44922Z");
                    ctx.save()
                    ctx.fillStyle = glyph_color;
                    ctx.translate(origin.x-25*scale_factor, origin.y-65*scale_factor);
                    ctx.scale(3 * scale_factor, 3 * scale_factor);
                    ctx.globalCompositeOperation = 'source-over';
                    ctx.fill(lock);
                    ctx.restore()
                }
                

                // Draw Label
                if (options.label) {
                  // Determine correct label string to use
                  if (typeof options.label === "boolean") {
                    label = \`$\{options.value\}%\`;
                  } else {
                    label = options.label;
                  }

                  ctx.save();
                  ctx.font = \`bold $\{45*scale_factor\}px -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif\`;
                  
                  // Align text for centering
                  ctx.textAlign = 'center'; // Center horizontally
                  ctx.textBaseline = 'middle'; // Center vertically

                  // Adjust font size
                  fitTextToWidth(ctx, label, 2*(radius - weight)-15);
                  console.log(label_origin);
                  ctx.fillText(label, label_origin.x, label_origin.y);
                  ctx.restore();
                }

                let charge = new Path2D(
                    "M 33.900002 22.563499 C 33.732738 22.218746 33.383186 21.999886 33 22 L 22.580002 22 L 29.903801 1.4277 C 30.05072 1.11795 30.028622 0.754509 29.845249 0.464844 C 29.661877 0.175175 29.342831 -0.000282 29 0 C 29 0 0.0874 32.590797 0.0874 32.590797 C -0.051372 32.900238 -0.023859 33.258919 0.160482 33.543571 C 0.344824 33.828224 0.660871 34.000053 1 34 L 10.759199 34 L 6.0229 55.787102 C 5.923433 56.242355 6.1516 56.705971 6.573009 56.904877 C 6.994419 57.103783 7.49736 56.985252 7.785601 56.619099 L 33.785599 23.619102 C 34.022514 23.318085 34.066925 22.908279 33.900002 22.563499 Z"
                  );
                let car_body = new Path2D(
                    "M 633.1875 204.421875 L 633.1875 204.53125 L 633.21875 204.640625 L 633.265625 204.78125 L 633.375 205.015625 L 633.578125 205.3125 L 633.96875 205.765625 L 634.921875 206.65625 L 636.359375 207.859375 L 637.484375 208.859375 L 638.21875 209.6875 L 638.71875 210.46875 L 639 211.125 L 639.171875 211.796875 L 639.25 212.609375 L 639.140625 213.40625 L 638.890625 214.1875 L 638.5 214.859375 L 638.0625 215.453125 L 637.75 215.78125 L 636.875 216.640625 L 635.015625 218.3125 L 633.03125 219.921875 L 630.953125 221.453125 L 628.78125 222.90625 L 626.53125 224.3125 L 624.234375 225.609375 L 621.875 226.875 L 619.46875 228.0625 L 617.046875 229.203125 L 614.578125 230.265625 L 612.125 231.28125 L 609.65625 232.234375 L 607.234375 233.125 L 604.796875 233.96875 L 602.421875 234.734375 L 598.9375 235.828125 L 594.53125 237.078125 L 590.484375 238.125 L 586.859375 239 L 582.390625 239.96875 L 578.90625 240.625 L 578.359375 240.703125 L 572.25 240.703125 L 573.578125 236.453125 L 574.09375 234.625 L 574.578125 232.59375 L 574.96875 230.609375 L 575.265625 228.671875 L 575.515625 226.59375 L 575.671875 224.65625 L 575.75 222.484375 L 575.765625 221.46875 L 575.75 220.109375 L 575.609375 217.40625 L 575.34375 214.765625 L 574.9375 212.1875 L 574.40625 209.625 L 573.765625 207.125 L 573 204.65625 L 572.125 202.265625 L 571.125 199.9375 L 570.015625 197.65625 L 568.796875 195.421875 L 567.546875 193.328125 L 566.09375 191.1875 L 564.640625 189.265625 L 562.96875 187.234375 L 561.296875 185.390625 L 559.515625 183.609375 L 557.75 182.015625 L 555.71875 180.34375 L 553.703125 178.828125 L 551.71875 177.484375 L 549.5 176.140625 L 547.234375 174.921875 L 544.9375 173.8125 L 542.59375 172.8125 L 540.328125 171.984375 L 537.8125 171.203125 L 535.359375 170.578125 L 532.6875 170.03125 L 530.109375 169.625 L 527.578125 169.375 L 524.78125 169.234375 L 523.484375 169.21875 L 522.203125 169.234375 L 519.40625 169.375 L 516.875 169.625 L 514.296875 170.03125 L 511.625 170.578125 L 509.171875 171.203125 L 506.65625 171.984375 L 504.390625 172.8125 L 502.046875 173.8125 L 499.65625 174.96875 L 497.421875 176.171875 L 495.265625 177.484375 L 493.28125 178.828125 L 491.265625 180.34375 L 489.234375 182.015625 L 487.390625 183.6875 L 485.609375 185.46875 L 484.015625 187.234375 L 482.34375 189.265625 L 480.828125 191.28125 L 479.484375 193.265625 L 478.109375 195.53125 L 476.90625 197.75 L 475.8125 200.03125 L 474.8125 202.390625 L 473.984375 204.65625 L 473.1875 207.234375 L 472.546875 209.75 L 472.03125 212.296875 L 471.625 214.90625 L 471.375 217.40625 L 471.234375 220.203125 L 471.21875 221.53125 L 471.234375 222.484375 L 471.3125 224.625 L 471.46875 226.5625 L 471.703125 228.640625 L 472 230.546875 L 472.390625 232.515625 L 472.828125 234.421875 L 473.375 236.375 L 474.640625 240.578125 L 404.015625 240.46875 L 290.46875 240.203125 L 217.265625 239.96875 L 180.578125 239.8125 L 181.796875 235.734375 L 182.296875 233.828125 L 182.703125 232 L 183.0625 230.109375 L 183.34375 228.21875 L 183.53125 226.421875 L 183.671875 224.390625 L 183.75 222.421875 L 183.765625 221.46875 L 183.75 220.109375 L 183.609375 217.40625 L 183.34375 214.765625 L 182.9375 212.1875 L 182.40625 209.625 L 181.765625 207.125 L 181 204.65625 L 180.125 202.265625 L 179.125 199.9375 L 178.015625 197.65625 L 176.796875 195.421875 L 175.546875 193.328125 L 174.09375 191.1875 L 172.640625 189.265625 L 170.96875 187.234375 L 169.296875 185.390625 L 167.515625 183.609375 L 165.75 182.015625 L 163.71875 180.34375 L 161.703125 178.828125 L 159.71875 177.484375 L 157.5 176.140625 L 155.234375 174.921875 L 152.9375 173.8125 L 150.59375 172.8125 L 148.328125 171.984375 L 145.8125 171.203125 L 143.359375 170.578125 L 140.6875 170.03125 L 138.109375 169.625 L 135.578125 169.375 L 132.78125 169.234375 L 131.484375 169.21875 L 130.203125 169.234375 L 127.40625 169.375 L 124.875 169.625 L 122.296875 170.03125 L 119.625 170.578125 L 117.171875 171.203125 L 114.65625 171.984375 L 112.390625 172.8125 L 110.046875 173.8125 L 107.65625 174.96875 L 105.421875 176.171875 L 103.265625 177.484375 L 101.28125 178.828125 L 99.265625 180.34375 L 97.234375 182.015625 L 95.390625 183.6875 L 93.609375 185.46875 L 92.015625 187.234375 L 90.34375 189.265625 L 88.828125 191.28125 L 87.484375 193.265625 L 86.109375 195.53125 L 84.90625 197.75 L 83.8125 200.03125 L 82.8125 202.390625 L 81.984375 204.65625 L 81.1875 207.234375 L 80.546875 209.75 L 80.03125 212.296875 L 79.625 214.90625 L 79.375 217.40625 L 79.234375 220.203125 L 79.21875 221.53125 L 79.234375 222.375 L 79.296875 224.21875 L 79.421875 226.125 L 79.59375 227.8125 L 79.84375 229.609375 L 79.859375 229.609375 L 80.171875 231.453125 L 80.15625 231.453125 L 80.515625 233.109375 L 80.9375 234.828125 L 82.109375 238.96875 L 74.84375 238.796875 L 71.171875 238.65625 L 70.015625 238.5625 L 69.5 238.453125 L 68.671875 238.25 L 67.578125 237.109375 L 66.3125 235.875 L 65.21875 234.84375 L 64.046875 233.828125 L 62.984375 232.9375 L 62 232.1875 L 61.09375 231.546875 L 60.21875 230.96875 L 58.796875 230.125 L 57.15625 229.265625 L 55.65625 228.59375 L 54.25 228.046875 L 54.25 228.0625 L 52.765625 227.515625 L 51.296875 226.9375 L 49.765625 226.296875 L 48.625 225.6875 L 47.828125 225.25 L 47.03125 224.71875 L 46.234375 224.140625 L 45.4375 223.484375 L 44.640625 222.765625 L 43.828125 221.953125 L 43.015625 221.0625 L 42.203125 220.09375 L 41.40625 219.046875 L 40.953125 218.46875 L 40.546875 217.859375 L 39.859375 216.71875 L 39.1875 215.453125 L 38.59375 214.109375 L 38.03125 212.703125 L 37.515625 211.203125 L 37.0625 209.640625 L 36.640625 208.03125 L 36.25 206.328125 L 35.921875 204.5625 L 35.625 202.75 L 35.359375 200.875 L 35.140625 198.921875 L 34.96875 196.953125 L 34.734375 193.890625 L 34.5625 189.65625 L 34.53125 185.265625 L 34.640625 180.71875 L 34.859375 176.125 L 35.203125 171.421875 L 35.65625 166.671875 L 36.234375 161.90625 L 36.921875 157.15625 L 37.71875 152.4375 L 38.609375 147.78125 L 39.59375 143.203125 L 40.6875 138.75 L 41.875 134.4375 L 43.15625 130.3125 L 44.171875 127.328125 L 44.875 125.40625 L 45.59375 123.546875 L 46.34375 121.734375 L 47.125 119.984375 L 47.90625 118.3125 L 48.71875 116.6875 L 49.5625 115.171875 L 50.40625 113.71875 L 51.296875 112.328125 L 52.21875 111.015625 L 53.140625 109.8125 L 54.109375 108.671875 L 55.109375 107.625 L 56.15625 106.671875 L 57.21875 105.828125 L 58.34375 105.078125 L 59.515625 104.46875 L 60.71875 103.96875 L 61.96875 103.625 L 62.59375 103.53125 L 63.375 103.40625 L 64.8125 103.15625 L 64.8125 103.140625 L 66.390625 102.8125 L 66.390625 102.828125 L 67.859375 102.484375 L 70.265625 101.84375 L 73.4375 100.890625 L 76.65625 99.78125 L 79.84375 98.5625 L 79.84375 98.546875 L 83.21875 97.140625 L 86.5625 95.625 L 89.953125 94 L 93.296875 92.28125 L 96.765625 90.421875 L 100.21875 88.5 L 103.65625 86.5 L 107.125 84.4375 L 110.578125 82.296875 L 114.03125 80.125 L 119.1875 76.796875 L 125.984375 72.265625 L 136 65.4375 L 145.5625 58.859375 L 151.6875 54.71875 L 157.53125 50.859375 L 161.71875 48.203125 L 164.40625 46.578125 L 165.71875 45.796875 L 166.546875 45.3125 L 168.25 44.40625 L 170.046875 43.53125 L 171.90625 42.703125 L 173.84375 41.890625 L 175.859375 41.140625 L 177.9375 40.390625 L 180.078125 39.703125 L 182.296875 39.03125 L 184.578125 38.390625 L 186.921875 37.796875 L 189.3125 37.21875 L 193.015625 36.390625 L 198.15625 35.40625 L 203.484375 34.515625 L 208.96875 33.734375 L 214.640625 33.046875 L 220.453125 32.4375 L 226.359375 31.921875 L 232.390625 31.46875 L 238.515625 31.109375 L 244.6875 30.828125 L 250.90625 30.609375 L 257.15625 30.4375 L 263.390625 30.34375 L 269.625 30.296875 L 275.84375 30.296875 L 281.984375 30.34375 L 291.078125 30.5 L 302.8125 30.8125 L 313.984375 31.25 L 324.4375 31.75 L 334.015625 32.28125 L 338.359375 32.5625 L 340.546875 32.71875 L 344.84375 33.140625 L 349.125 33.703125 L 353.375 34.40625 L 357.609375 35.21875 L 361.8125 36.203125 L 365.984375 37.265625 L 370.15625 38.46875 L 374.3125 39.765625 L 378.4375 41.171875 L 382.578125 42.6875 L 386.6875 44.3125 L 390.796875 46.015625 L 394.921875 47.796875 L 399.046875 49.671875 L 403.140625 51.625 L 407.265625 53.640625 L 411.40625 55.734375 L 415.546875 57.875 L 419.71875 60.09375 L 426 63.515625 L 434.453125 68.234375 L 447.3125 75.5625 L 460.5625 83.140625 L 469.59375 88.25 L 474.203125 90.8125 L 474.671875 91.0625 L 475.6875 91.59375 L 477.359375 92.375 L 479.5625 93.25 L 481.90625 94.0625 L 484.484375 94.8125 L 487.046875 95.46875 L 489.640625 96.03125 L 492.421875 96.546875 L 495.328125 97.015625 L 498.21875 97.4375 L 498.21875 97.421875 L 502.828125 97.984375 L 512.40625 98.96875 L 522.5625 99.984375 L 527.8125 100.578125 L 531.359375 101.046875 L 534.921875 101.5625 L 538.53125 102.140625 L 542.171875 102.8125 L 545.828125 103.5625 L 549.5 104.40625 L 553.1875 105.359375 L 556.890625 106.421875 L 560.59375 107.609375 L 564.296875 108.9375 L 567.96875 110.40625 L 570.75 111.609375 L 572.59375 112.46875 L 574.421875 113.359375 L 576.265625 114.3125 L 577.171875 114.796875 L 579.125 115.84375 L 582.921875 117.984375 L 586.65625 120.1875 L 590.296875 122.4375 L 593.828125 124.75 L 597.265625 127.09375 L 600.59375 129.5 L 603.828125 131.953125 L 606.921875 134.453125 L 609.921875 137 L 612.765625 139.578125 L 615.5 142.21875 L 618.09375 144.890625 L 620.546875 147.59375 L 622.859375 150.359375 L 625.015625 153.15625 L 626.515625 155.265625 L 627.484375 156.71875 L 628.390625 158.15625 L 629.265625 159.578125 L 630.109375 161.046875 L 630.890625 162.515625 L 631.640625 164 L 632.34375 165.484375 L 632.984375 166.96875 L 633.59375 168.484375 L 634.15625 169.984375 L 634.671875 171.5 L 635.140625 173.03125 L 635.546875 174.578125 L 635.90625 176.125 L 636.21875 177.671875 L 636.484375 179.234375 L 636.6875 180.796875 L 636.84375 182.359375 L 636.953125 183.9375 L 636.984375 185.53125 L 636.96875 187.109375 L 636.90625 188.6875 L 636.78125 190.296875 L 636.59375 191.890625 L 636.359375 193.5 L 636.046875 195.109375 L 635.6875 196.6875 L 635.265625 198.3125 L 634.765625 199.9375 L 634.234375 201.53125 L 633.625 203.125 L 633.3125 203.921875 L 633.234375 204.15625 Z"
                  );
            
                if (options.charging) {
                  ctx.save();
                  ctx.fillStyle = glyph_color;
                  ctx.translate(origin.x - 15 * scale_factor, 2);
                  ctx.scale(0.8 * scale_factor, 0.8 * scale_factor);
                  ctx.globalCompositeOperation = 'destination-out';
                  ctx.lineWidth = weight / 1.5;
                  ctx.stroke(charge);
                  ctx.globalCompositeOperation = 'source-over';
                  ctx.fill(charge);
                  ctx.restore();
                } else if (options.plugged_in) {
                  ctx.save();
                  ctx.fillStyle = glyph_color;
                  plug = new Path2D(
                    "M 5.44 39.959999 L 21.280001 39.959999 L 21.280001 8.090004 C 21.280001 3.57 24.98 -0.129997 29.5 -0.129997 L 29.5 -0.129997 C 34.02 -0.129997 37.720001 3.57 37.720001 8.090004 L 37.720001 39.959999 L 61.849998 39.959999 L 61.849998 8.090004 C 61.849998 3.57 65.550003 -0.129997 70.07 -0.129997 L 70.07 -0.129997 C 74.589996 -0.129997 78.290001 3.57 78.290001 8.090004 L 78.290001 39.959999 L 93.709999 39.959999 C 96.57 39.959999 98.900002 42.300003 98.900002 45.150002 L 98.900002 51.169998 C 98.900002 54.029999 96.559998 56.360001 93.709999 56.360001 L 5.44 56.360001 C 2.58 56.360001 0.25 54.020004 0.25 51.169998 L 0.25 45.150002 C 0.25 42.290001 2.59 39.959999 5.44 39.959999 Z M 9.52 56.459999 L 9.52 69.039993 C 9.51 91.100006 19.309999 101.889999 41.790001 104.600006 L 41.790001 122.75 L 58.23 122.75 L 58.23 104.400002 C 80.480003 102.260002 90.5 89.179993 90.5 67.809998 L 90.5 56.459999 Z"
                  );
                  ctx.translate(origin.x - 15 * scale_factor, 3);
                  ctx.scale(0.4 * scale_factor, 0.4 * scale_factor);
                  ctx.globalCompositeOperation = 'destination-out';
                  ctx.lineWidth = weight;
                  ctx.stroke(plug);
                  ctx.globalCompositeOperation = 'source-over';
                  ctx.fill(plug);
                  ctx.restore();
                }

                // Draw behind-body car status indicators
                
                let bolt_pos = {x: car_pos.x+68.5, y: car_pos.y+30.5};
                let bolt_scale = {x: car_scale.x*1.5, y: car_scale.x*1.5};

                if (options.show_car_status) {
                    // Draw Liftgate
                    if(options.liftgate_open) {
                      ctx.save();
                      liftgate = new Path2D("M 7.561163 112.337189 C 21.807734 84.010544 46.352863 53.672546 59.611622 57.223557 C 91.849358 65.857529 146.606522 49.329285 178.140884 45.570145 C 215.900925 41.068878 299.781342 81.360199 340.250092 102.162888");
    
                      ctx.translate(car_pos.x, car_pos.y);
                      ctx.scale(car_scale.x, car_scale.y);
    
                      ctx.lineWidth=20;
                      ctx.stroke(liftgate);
                      ctx.globalCompositeOperation = 'destination-out';
                      ctx.stroke(car_body);
                      ctx.restore();
    
                    }

                } else {
                  // Adjust bolt position
                    bolt_pos.y -= 10;
                    bolt_scale = {x: car_scale.x*2, y: car_scale.x*2};
                }

                  // Draw Car

                  ctx.save();
                  wheels = new Path2D("M 135.328125 171.625 L 137.859375 171.890625 L 140.34375 172.265625 L 142.78125 172.765625 L 145.1875 173.390625 L 147.53125 174.109375 L 149.828125 174.953125 L 152.078125 175.90625 L 154.265625 176.96875 L 156.390625 178.109375 L 158.4375 179.359375 L 160.4375 180.71875 L 162.359375 182.15625 L 164.21875 183.6875 L 165.984375 185.296875 L 167.6875 187 L 169.296875 188.765625 L 170.828125 190.609375 L 172.265625 192.546875 L 173.625 194.546875 L 174.875 196.59375 L 176.015625 198.71875 L 177.078125 200.90625 L 178.03125 203.15625 L 178.875 205.453125 L 179.59375 207.796875 L 180.21875 210.203125 L 180.71875 212.640625 L 181.09375 215.125 L 181.359375 217.65625 L 181.484375 220.203125 L 181.484375 222.78125 L 181.359375 225.328125 L 181.09375 227.859375 L 180.71875 230.34375 L 180.21875 232.78125 L 179.59375 235.1875 L 178.875 237.53125 L 178.03125 239.828125 L 177.078125 242.078125 L 176.015625 244.265625 L 174.875 246.390625 L 173.625 248.4375 L 172.265625 250.4375 L 170.828125 252.375 L 169.296875 254.21875 L 167.6875 255.984375 L 165.984375 257.6875 L 164.21875 259.296875 L 162.359375 260.828125 L 160.4375 262.265625 L 158.4375 263.625 L 156.390625 264.875 L 154.265625 266.015625 L 152.078125 267.078125 L 149.828125 268.03125 L 147.53125 268.875 L 145.1875 269.59375 L 142.78125 270.21875 L 140.34375 270.71875 L 137.859375 271.09375 L 135.328125 271.359375 L 132.796875 271.484375 L 131.484375 271.5 L 130.1875 271.484375 L 127.640625 271.359375 L 125.125 271.09375 L 122.640625 270.71875 L 120.203125 270.21875 L 117.796875 269.59375 L 115.453125 268.875 L 113.15625 268.03125 L 110.90625 267.078125 L 108.71875 266.015625 L 106.59375 264.875 L 104.546875 263.625 L 102.53125 262.265625 L 100.609375 260.828125 L 98.765625 259.296875 L 97 257.6875 L 95.296875 255.984375 L 93.6875 254.21875 L 92.15625 252.375 L 90.71875 250.4375 L 89.359375 248.4375 L 88.109375 246.390625 L 86.96875 244.265625 L 85.90625 242.078125 L 84.953125 239.828125 L 84.125 237.546875 L 83.375 235.1875 L 82.765625 232.78125 L 82.265625 230.34375 L 81.890625 227.859375 L 81.625 225.328125 L 81.5 222.796875 L 81.484375 221.5 L 81.5 220.1875 L 81.625 217.65625 L 81.890625 215.125 L 82.265625 212.640625 L 82.765625 210.203125 L 83.375 207.796875 L 84.125 205.4375 L 84.953125 203.15625 L 85.90625 200.90625 L 86.96875 198.71875 L 88.109375 196.59375 L 89.359375 194.546875 L 90.71875 192.546875 L 92.15625 190.609375 L 93.6875 188.765625 L 95.296875 187 L 97 185.296875 L 98.765625 183.6875 L 100.609375 182.15625 L 102.53125 180.71875 L 104.546875 179.359375 L 106.59375 178.109375 L 108.71875 176.96875 L 110.90625 175.90625 L 113.15625 174.953125 L 115.453125 174.109375 L 117.796875 173.390625 L 120.203125 172.765625 L 122.640625 172.265625 L 125.125 171.890625 L 127.640625 171.625 L 130.203125 171.5 L 132.78125 171.5 Z M 527.328125 171.625 L 529.859375 171.890625 L 532.34375 172.265625 L 534.78125 172.765625 L 537.1875 173.390625 L 539.53125 174.109375 L 541.828125 174.953125 L 544.078125 175.90625 L 546.265625 176.96875 L 548.390625 178.109375 L 550.4375 179.359375 L 552.4375 180.71875 L 554.359375 182.15625 L 556.21875 183.6875 L 557.984375 185.296875 L 559.6875 187 L 561.296875 188.765625 L 562.828125 190.609375 L 564.265625 192.546875 L 565.625 194.546875 L 566.875 196.59375 L 568.015625 198.71875 L 569.078125 200.90625 L 570.03125 203.15625 L 570.875 205.453125 L 571.59375 207.796875 L 572.21875 210.203125 L 572.71875 212.640625 L 573.09375 215.125 L 573.359375 217.65625 L 573.484375 220.203125 L 573.484375 222.78125 L 573.359375 225.328125 L 573.09375 227.859375 L 572.71875 230.34375 L 572.21875 232.78125 L 571.59375 235.1875 L 570.875 237.53125 L 570.03125 239.828125 L 569.078125 242.078125 L 568.015625 244.265625 L 566.875 246.390625 L 565.625 248.4375 L 564.265625 250.4375 L 562.828125 252.375 L 561.296875 254.21875 L 559.6875 255.984375 L 557.984375 257.6875 L 556.21875 259.296875 L 554.359375 260.828125 L 552.4375 262.265625 L 550.4375 263.625 L 548.390625 264.875 L 546.265625 266.015625 L 544.078125 267.078125 L 541.828125 268.03125 L 539.53125 268.875 L 537.1875 269.59375 L 534.78125 270.21875 L 532.34375 270.71875 L 529.859375 271.09375 L 527.328125 271.359375 L 524.796875 271.484375 L 523.484375 271.5 L 522.1875 271.484375 L 519.640625 271.359375 L 517.125 271.09375 L 514.640625 270.71875 L 512.203125 270.21875 L 509.796875 269.59375 L 507.453125 268.875 L 505.15625 268.03125 L 502.90625 267.078125 L 500.71875 266.015625 L 498.59375 264.875 L 496.546875 263.625 L 494.53125 262.265625 L 492.609375 260.828125 L 490.765625 259.296875 L 489 257.6875 L 487.296875 255.984375 L 485.6875 254.21875 L 484.15625 252.375 L 482.71875 250.4375 L 481.359375 248.4375 L 480.109375 246.390625 L 478.96875 244.265625 L 477.90625 242.078125 L 476.953125 239.828125 L 476.125 237.546875 L 475.375 235.1875 L 474.765625 232.78125 L 474.265625 230.34375 L 473.890625 227.859375 L 473.625 225.328125 L 473.5 222.796875 L 473.484375 221.5 L 473.5 220.1875 L 473.625 217.65625 L 473.890625 215.125 L 474.265625 212.640625 L 474.765625 210.203125 L 475.375 207.796875 L 476.125 205.4375 L 476.953125 203.15625 L 477.90625 200.90625 L 478.96875 198.71875 L 480.109375 196.59375 L 481.359375 194.546875 L 482.71875 192.546875 L 484.15625 190.609375 L 485.6875 188.765625 L 487.296875 187 L 489 185.296875 L 490.765625 183.6875 L 492.609375 182.15625 L 494.53125 180.71875 L 496.546875 179.359375 L 498.59375 178.109375 L 500.71875 176.96875 L 502.90625 175.90625 L 505.15625 174.953125 L 507.453125 174.109375 L 509.796875 173.390625 L 512.203125 172.765625 L 514.640625 172.265625 L 517.125 171.890625 L 519.640625 171.625 L 522.203125 171.5 L 524.78125 171.5 Z");
                  window_f = new Path2D("M 321.609375 48.234375 L 344.390625 50.5625 L 363.484375 54.203125 L 371.828125 56.4375 L 381.796875 59.75 L 388.21875 62.34375 L 396.09375 66.15625 L 408.0625 73.546875 L 417.78125 81.4375 L 432.828125 95.578125 L 432.421875 95.96875 L 428.171875 97.5 L 293.78125 97.5 L 299.234375 47.5625 Z");
                  window_r = new Path2D("M 272.765625 97.5 L 144.515625 97.5 L 140.9375 95.09375 L 139.640625 93.109375 L 139.625 91.703125 L 140.578125 90.046875 L 151.859375 79.171875 L 158.140625 74 L 165.890625 68.765625 L 171.890625 65.4375 L 179.046875 62.15625 L 185.96875 59.515625 L 195.375 56.59375 L 205.796875 54.03125 L 228.171875 50.328125 L 251.09375 48.3125 L 278.203125 47.578125 Z");

                  ctx.translate(car_pos.x, car_pos.y);
                  ctx.scale(car_scale.x, car_scale.y);
                  ctx.fill(car_body);
                  ctx.fill(wheels);

                  ctx.globalCompositeOperation = 'destination-out';
                  ctx.lineWidth=5;
                  ctx.stroke(wheels);
                  ctx.restore();
                  ctx.save();
                  ctx.globalCompositeOperation = 'destination-out';
                  ctx.translate(bolt_pos.x, bolt_pos.y);
                  ctx.scale(bolt_scale.x, bolt_scale.y);
                  ctx.fill(charge);
                  ctx.restore();

                  // Draw foreground car status indicators

                  if (options.show_car_status) {
                    ctx.save();
                    ctx.translate(car_pos.x, car_pos.y);
                    ctx.scale(car_scale.x, car_scale.y);
                    ctx.globalCompositeOperation = 'destination-out';
                    ctx.lineWidth=5;
                    ctx.stroke(window_f);
                    ctx.stroke(window_r);
                    ctx.restore();
    
                    // Draw Open Window - Front
                    if (options.window_f_open) {
                      ctx.save();
                      window_open_f = new Path2D("M 294 77 C 294 77 296.842621 45 297 45 C 399.999878 45 417.941711 80.531921 434.652344 93.863281 C 439.365631 97.623413 428.585938 100 428.585938 100 L 404.28125 100 C 385.190704 87.966248 354.221558 77 297 77 C 296.772552 77 294 77 294 77 Z");
    
                      ctx.translate(car_pos.x, car_pos.y);
                      ctx.scale(car_scale.x, car_scale.y);
                      ctx.globalCompositeOperation = 'destination-out';
    
                      ctx.fill(window_open_f);
    
                      ctx.restore();
                    }
    
                    // Draw Open Window - Rear
                    if (options.window_r_open) {
                      ctx.save();
                      window_open_r = new Path2D("M 143.759964 100 C 143.759964 100 131.750061 94.762634 139.562698 87.496094 C 155.424728 72.742783 174.000305 45 281.000214 45 C 281.122559 45 279.269989 61.84024 277.578339 77.011719 C 212.209595 77.38031 180.689072 88.307632 162.392776 100 L 143.759964 100 Z");
    
                      ctx.translate(car_pos.x, car_pos.y);
                      ctx.scale(car_scale.x, car_scale.y);
                      ctx.globalCompositeOperation = 'destination-out';
    
                      ctx.fill(window_open_r);
    
                      ctx.restore();
                    }
    
                    // Draw Open Door - Front
                    if (options.door_open) {
                      ctx.save();
                      interior = new Path2D("M 333.125 37.234375 L 343.5 38.015625 L 343.5 38 L 350.40625 38.96875 L 361.03125 41.15625 L 371.46875 44.109375 L 381.75 47.75 L 392.484375 52.25 L 392.484375 227.5 L 292.25 227.46875 L 291.28125 227.28125 L 290.640625 226.828125 L 290.25 226.078125 L 289.359375 222.4375 L 287.296875 216.5625 L 286.015625 211.4375 L 284.0625 198.703125 L 283.265625 185.703125 L 283.390625 168.171875 L 284.96875 145.171875 L 288.75 116.125 L 296 35.578125 Z");
                      door_f_open = new Path2D("M 300.984375 24.8125 L 305.125 25.328125 L 311 26.140625 L 318.171875 27.234375 L 324.78125 28.34375 L 333.921875 30.046875 L 342.453125 31.6875 L 348.078125 32.71875 L 348.078125 32.703125 L 350.9375 33.203125 L 352.578125 33.5 L 355.875 34.140625 L 359.171875 34.890625 L 362.453125 35.71875 L 365.734375 36.640625 L 368.984375 37.640625 L 372.234375 38.71875 L 375.484375 39.875 L 378.703125 41.109375 L 381.890625 42.4375 L 385.078125 43.8125 L 388.25 45.25 L 391.40625 46.78125 L 394.546875 48.375 L 397.640625 50.015625 L 400.734375 51.734375 L 403.796875 53.5 L 406.84375 55.34375 L 409.859375 57.21875 L 412.859375 59.171875 L 415.828125 61.171875 L 418.75 63.203125 L 421.671875 65.296875 L 424.546875 67.4375 L 427.40625 69.625 L 430.21875 71.84375 L 433.015625 74.09375 L 435.765625 76.40625 L 438.484375 78.75 L 441.171875 81.125 L 443.8125 83.515625 L 446.4375 85.96875 L 447.515625 87 L 447.75 87.140625 L 448.6875 87.828125 L 449.59375 88.703125 L 450.421875 89.65625 L 451.171875 90.703125 L 451.890625 91.84375 L 452.546875 93.078125 L 453.171875 94.40625 L 453.765625 95.8125 L 454.328125 97.3125 L 454.859375 98.90625 L 455.359375 100.5625 L 455.828125 102.328125 L 456.296875 104.140625 L 456.921875 107.03125 L 457.6875 111.125 L 458.359375 115.5 L 458.96875 120.125 L 459.484375 125 L 459.9375 130.0625 L 460.296875 135.296875 L 460.609375 140.6875 L 460.84375 146.203125 L 461.015625 151.84375 L 461.125 157.5625 L 461.171875 163.3125 L 461.171875 169.125 L 461.125 174.9375 L 461.015625 180.734375 L 460.859375 186.484375 L 460.65625 192.171875 L 460.421875 197.765625 L 460.125 203.25 L 459.8125 208.578125 L 459.453125 213.765625 L 459.046875 218.734375 L 458.640625 223.5 L 458.1875 228.03125 L 457.71875 232.28125 L 457.4375 234.71875 L 457.046875 235.5 L 456.5 236.21875 L 455.890625 236.8125 L 455.25 237.3125 L 454.46875 237.8125 L 453.671875 238.21875 L 452.8125 238.625 L 451.859375 238.984375 L 450.375 239.484375 L 448.125 240.109375 L 445.625 240.6875 L 442.859375 241.234375 L 439.890625 241.765625 L 436.671875 242.234375 L 433.296875 242.703125 L 429.734375 243.125 L 424.15625 243.71875 L 416.265625 244.40625 L 408.09375 245.046875 L 399.8125 245.59375 L 387.53125 246.3125 L 372.4375 247.078125 L 363.015625 247.5625 L 357.859375 247.875 L 355.6875 248.03125 L 355.21875 248.046875 L 354.328125 248 L 353.4375 247.859375 L 352.59375 247.59375 L 351.8125 247.25 L 351.125 246.84375 L 350.453125 246.359375 L 349.890625 245.828125 L 349.140625 245.046875 L 348.3125 243.921875 L 347.3125 242.328125 L 346.734375 241.296875 L 346.390625 240.609375 L 345.75 239.171875 L 345.21875 237.609375 L 344.765625 235.953125 L 344.421875 234.203125 L 344.109375 232.34375 L 343.890625 230.375 L 343.71875 228.296875 L 343.59375 226.09375 L 343.515625 223.796875 L 343.46875 220.109375 L 343.53125 214.75 L 343.65625 208.90625 L 343.921875 199.171875 L 344.140625 188.015625 L 344.203125 179.953125 L 344.15625 171.28125 L 344.015625 164.375 L 343.859375 159.609375 L 343.671875 154.640625 L 343.40625 149.578125 L 343.09375 144.328125 L 342.71875 138.9375 L 342.5 136.203125 L 342.515625 136.203125 L 342.375 134.75 L 342 131.671875 L 341.515625 128.65625 L 340.921875 125.625 L 340.21875 122.546875 L 339.40625 119.421875 L 338.5 116.296875 L 337.5 113.125 L 336.40625 109.96875 L 335.21875 106.734375 L 333.953125 103.484375 L 332.625 100.203125 L 331.203125 96.921875 L 329.734375 93.609375 L 328.203125 90.296875 L 328.1875 90.296875 L 326.578125 86.90625 L 324.078125 81.8125 L 320.59375 74.90625 L 315.125 64.453125 L 307.546875 50.171875 L 301.859375 39.25 L 298.125 31.859375 L 295.625 26.828125 L 297.34375 24.390625 Z");
                      window_f_door_open = new Path2D("M 341.875 43.203125 L 352.96875 45.546875 L 363.640625 48.3125 L 374.25 51.671875 L 374.25 51.6875 L 386.796875 56.4375 L 386.796875 56.421875 L 394.28125 59.71875 L 404.546875 64.921875 L 413.09375 70.0625 L 420.546875 75.375 L 426.59375 80.46875 L 433.25 87.234375 L 439.375 95.109375 L 444.65625 103.953125 L 445.203125 106.03125 L 444.765625 107.578125 L 443.703125 108.75 L 350.59375 97.671875 L 319.875 39.609375 Z");
                      window_f_open_door_open = new Path2D("M 444.688293 111.392883 L 443.582825 111.262024 C 433.059357 102.335159 417.804199 93.107056 395.000793 85.000305 C 375.281586 77.98999 358.242462 74.990036 333.701965 71.39093 C 324.6633 54.439331 315.046356 36.293762 315.323059 36.33429 C 340.071136 39.958649 357.178436 42.953308 377.000793 50.000305 C 425.196991 67.134369 439.694366 89.276413 447.000793 103.000305 C 449.705231 108.080154 444.688293 111.392883 444.688293 111.392883 Z");
    
                      ctx.translate(car_pos.x, car_pos.y);
                      ctx.scale(car_scale.x, car_scale.y);
                      ctx.fillStyle = bg_color;
                      ctx.fill(interior);
                      ctx.fillStyle = options.fg_color;
                      ctx.globalCompositeOperation = 'destination-out';
                      ctx.lineWidth = 5;
                      ctx.stroke(interior);
                      
                      ctx.globalCompositeOperation = 'source-over';
                      ctx.fill(door_f_open);
    
                      ctx.globalCompositeOperation = 'destination-out';
                      ctx.stroke(door_f_open);
                      ctx.stroke(window_f_door_open);
    
                      // Draw Open Window - Front
                      if (options.window_f_open) {
                        ctx.fill(window_f_open_door_open);
                      }
    
                      ctx.restore();
                    }
                }

                
              }
            }
            
            function pointOnCircle(origin, radius, angle) {
              return {
                x: origin.x + radius * Math.cos(angle),
                y: origin.y + radius * Math.sin(angle),
              };
            }
            
            function rounded_arc(ctx, origin, radius, weight, start, end) {
              let cap_radius = weight / 2;
              let sAngle = 0.5 * Math.PI + 2 * Math.PI * start;
              let eAngle = 0.5 * Math.PI + 2 * Math.PI * end;
              let e_center = pointOnCircle(origin, radius - weight / 2, eAngle);
              let s_center = pointOnCircle(origin, radius - weight / 2, sAngle);
            
              ctx.beginPath();
              ctx.arc(origin.x, origin.y, radius, sAngle, eAngle);
              ctx.arc(
                e_center.x,
                e_center.y,
                cap_radius,
                eAngle,
                (eAngle - Math.PI) % (2 * Math.PI)
              );
              ctx.arc(origin.x, origin.y, radius - weight, eAngle, sAngle, true);
              ctx.arc(
                s_center.x,
                s_center.y,
                cap_radius,
                (sAngle - Math.PI) % (2 * Math.PI),
                sAngle
              );
              ctx.closePath();
            }

            function fitTextToWidth(ctx, text, maxWidth) {
              let currentFont = ctx.font;
              // Find a match for the font size and unit (e.g., "16px")
              const fontSizeRegex = /(\b\d+(\.\d+)?(px|pt|em|%)\b)/;
              let match = currentFont.match(fontSizeRegex);

              if (!match) return; // If no match was found, exit the function

              let fullMatch = match[0]; // The full match of the size and unit, e.g., "16px"
              let size = parseFloat(match[1]); // The numeric part of the size
              let unit = match[3]; // The unit of the size

              // Dynamically decrease the font size until the text fits the maxWidth
              let newSize = size;
              do {
                  // Reconstruct the font string with the new size
                  ctx.font = currentFont.replace(fullMatch, \`$\{newSize\}$\{unit\}\`);
                  let textWidth = ctx.measureText(text).width;
                  if (textWidth <= maxWidth) break; // If it fits, stop adjusting
                  newSize -= 1; // Decrement the font size
              } while (newSize > 0);

              // Return the font string with the adjusted size
              return ctx.font;
          }
            
            draw(${JSON.stringify(options)});
        </script>
        </body>
        </html>
        `;

    // Load the HTML content in the WebView
    await wv.loadHTML(htmlContent);

    // Run the JavaScript in the WebView
    let js = "document.getElementById('canvas').toDataURL();";

    let base64Image = await wv.evaluateJavaScript(js);
    let image_data = Data.fromBase64String(base64Image.replace(/^data:image\/[a-z]+;base64,/, ""))

    // Now 'base64Image' contains a base64-encoded PNG of the canvas
    let image = Image.fromData(image_data)
    return image
}

function getTimeDifferenceDescription(date) {
    let now = new Date();
    let diffInMilliseconds = now - date;

    let seconds = diffInMilliseconds / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    let weeks = days / 7;
    let months = days / 30;

    if (months >= 1) {
        return `${Math.floor(months)} month${Math.floor(months) > 1 ? 's' : ''} ago`;
    } else if (weeks >= 1) {
        return `${Math.floor(weeks)} week${Math.floor(weeks) > 1 ? 's' : ''} ago`;
    } else if (days >= 1) {
        if (Math.floor(days) > 1 && days % 1 >= 0.5) {
            return `${Math.floor(days)} days and ${Math.round((days % 1) * 24)} hours ago`;
        } else {
            return `${Math.floor(days)} day${Math.floor(days) > 1 ? 's' : ''} ago`;
        }
    } else if (hours >= 1) {
        if (Math.floor(hours) > 1 && hours % 1 >= 0.5) {
            return `${Math.floor(hours)} hours and ${Math.round((hours % 1) * 60)} minutes ago`;
        } else {
            return `${Math.floor(hours)} hour${Math.floor(hours) > 1 ? 's' : ''} ago`;
        }
    } else if (minutes >= 1) {
        return `${Math.floor(minutes)} minute${Math.floor(minutes) > 1 ? 's' : ''} ago`;
    } else {
        return `${Math.floor(seconds)} second${Math.floor(seconds) !== 1 ? 's' : ''} ago`;
    }
}

async function main(options = {}) {
    let tba = new ToybaruApp({tokenId: options.tokenId})
    await tba.init();

    widget_options = await get_vehicle_widget_values(tba.vehicle);
    // console.log(JSON.stringify(widget_options, undefined, 4));
    // console.log(`data:image/png;base64,${Data.fromPNG(SFSymbol.named("lock.open.fill").image).toBase64String()}`);
    console.log(`EV Status: ${getTimeDifferenceDescription(tba.vehicle.last_ev_timestamp)}`);
    console.log(`Vehicle Status: ${getTimeDifferenceDescription(tba.vehicle.last_status_timestamp)}`);
    console.log(`Next Refresh: ${getTimeDifferenceDescription(tba.vehicle.next_refresh)}`);

    widget = await createAccessoryWidget({value: widget_options.value});
    widget.refreshAfterDate = new Date(tba.vehicle.next_refresh);
    widget.presentAccessoryCircular();
    Script.complete();}

await main(args.queryParameters);
