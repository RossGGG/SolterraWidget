// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: deep-green; icon-glyph: user-circle;

class ToybaruAuth {
    configuration = {
        realm: "https://login.subarudriverslogin.com/oauth2/realms/root/realms/tmna-native",
        client_id: "oneappsdkclient",
        scope: "openid profile write",
        redirect_uri: "com.toyota.oneapp:/oauth2Callback",
        cookie_name: "iPlanetDirectoryPro",
        sign_in_providers: {
            Apple: {
                request: "https://appleid.apple.com/auth/authorize",
                redirect_uri: "/appleSignIn.jsp?service%3DOneAppSignIn",
                request_params: {
                    client_id: "com.subaru.fr.prod",
                    response_type: "code",
                    response_mode: "query",
                    //response_mode: "form_post",
                    //scope: "openid email name",
                }
            }
        }
    }
    tokens = {}
    tokenId = null;
    auth_code = null;

    constructor(options= {}) {
        const {tokenId = null, auth_code = null, tokens = null} = options;
        this.tokenId = tokenId;
        this.auth_code = auth_code;
        this.tokens = tokens;
    }

    // Discover OIDC configuration
    async discoverOIDCConfig(realm=null) {
        console.log("Obtaining OID Configuration...")
        const url = `${realm || this.configuration.realm}/.well-known/openid-configuration`;
        const req = new Request(url);
        const config = await req.loadJSON();
        console.log("Done.")
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
        this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options))
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

    async check_tokens() {
        if (this.tokens && this.tokens.hasOwnProperty("expires_at")) {
            if (Date.now() > this.tokens.expires_at) {
                return await this.refresh_tokens();
            }
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

        this.tokens = await this.Utilities.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options))
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
            // console.log("Extracting")
            // console.log(tokens)
            tokens["guid"] = await this.parseJwt(tokens["id_token"], jwt_keys)["sub"]
            tokens["updated_at"] = Date.now()
            tokens["expires_at"] = tokens["updated_at"] + tokens["expires_in"]

            //console.log("tokens retrieved")

            //save_tokens(tokens)
            return tokens
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

}
async function load_tokens(auth_instance) {
    let tokens = {}
    if (Keychain.contains("subaru_tokens")) {
        tokens = JSON.parse(Keychain.get("subaru_tokens"))
        auth_instance.tokens = tokens;
        let result = await auth_instance.check_tokens();
        save_tokens(auth_instance)
    }

    return tokens
}

function save_tokens(auth_instance) {
    Keychain.set("subaru_tokens", JSON.stringify(auth_instance.tokens))
    console.log("Tokens Stored");
}

async function login() {
    let fm = FileManager.iCloud();
    let path = fm.joinPath(fm.documentsDirectory(), "ToybaruLogin.html")
    let url = `file://${path}?success=${URLScheme.forRunningScript()}`
    console.log(url);

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
// Example usage
async function main(options = {}) {
    console.log("start");
    let tba = new ToybaruAuth({tokenId: options.tokenId});

    if (tba.tokenId) {
        await tba.acquire_tokens();
        save_tokens(tba);
    } else {
        await load_tokens(tba);
    }

    console.log(`TOKENS: ${JSON.stringify(tba.tokens)}`)

    if (tba.tokens) {
        new Alert("You are logged in.")
    } else {
        console.log("Logging in");
        await login();
    }
}

await main(args.queryParameters);
