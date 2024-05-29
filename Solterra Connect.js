// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: red; icon-glyph: car;

const WebApp = null;

const DEBUG= true;
const logName = `${Script.name()}.${Device.name()}.${Device.model()}.${Date.now()}.log`;

class DebugLogger {
    // Handle writing log message to the log file
    static async _write_log(message, level) {
        const logMessage = `[${new Date().toLocaleString()}] [${level}] ${message}`;

        let fm;
        try {
            fm = FileManager.iCloud();
        } catch (e) {
            fm = FileManager.local();
        }
        const path = fm.joinPath(fm.documentsDirectory(), `${Script.name()}/logs/${logName}`);

        let log = '';

        if (fm.fileExists(path)) {
            await fm.downloadFileFromiCloud(path);
            log += fm.readString(path);
        }

        log += logMessage + '\n';
        fm.writeString(path, log);
    }

    static log(message, console=DEBUG, level='log') {
        if (!["log", "warn", "error"].includes(level)) {
            level = 'log';
        }

        if (console) {
            console[level](logMessage);
        }

        this._write_log(message, level).then();
    }

    static error(message, console) {
        this.log(message, console, 'error');
    }

    static warn(message, console) {
        this.log(message, console, 'warn');
    }
}

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

class Utilities {
    static hexColorBrightness(hex) {
        // Remove the hash from the hex color if it exists
        const hexColor = hex.replace('#', '');

        // Convert the hex color to RGB
        let r = parseInt(hexColor.substring(0, 2), 16);
        let g = parseInt(hexColor.substring(2, 4), 16);
        let b = parseInt(hexColor.substring(4, 6), 16);

        // Calculate the brightness as a value from 0-1
        return (0.299 * r + 0.587 * g + 0.114 * b) / 255;

    }

    static darkenHexColor(hex, percent) {
        // Ensure hex is formatted properly and percent is a decimal (e.g., 20% should be 0.2)
        const f = parseInt(hex.slice(1), 16);
        const p = percent < 0 ? 0 : percent;
        const R = f >> 16;
        const G = (f >> 8) & 0x00FF;
        const B = f & 0x0000FF;

        // Calculate the new color values after darkening
        const newR = Math.round(R * (1 - p));
        const newG = Math.round(G * (1 - p));
        const newB = Math.round(B * (1 - p));

        // Convert the RGB values back to hex format
        return "#" + (0x1000000 + newR * 0x10000 + newG * 0x100 + newB).toString(16).slice(1);
    }

    static desaturateBase64Image(base64String) {
        if (base64String && !base64String.startsWith("data:image/png;base64,")) {
            base64String = `data:image/png;base64,${base64String}`;
        }

        return new Promise((resolve, reject) => {
            // Create an Image object
            const img = new Image();
            img.src = base64String;

            img.onload = function () {
                // Get the canvas and its context
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                // Set canvas dimensions to match the image
                canvas.width = img.width;
                canvas.height = img.height;

                // Draw the image onto the canvas
                ctx.drawImage(img, 0, 0);

                // Get image data from the canvas
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const data = imageData.data;

                // Loop through each pixel and desaturate
                for (let i = 0; i < data.length; i += 4) {
                    const r = data[i];
                    const g = data[i + 1];
                    const b = data[i + 2];

                    // Calculate the average (grayscale value)
                    const gray = 0.3 * r + 0.59 * g + 0.11 * b;

                    // Set the red, green, and blue channels to the gray value
                    data[i] = gray;
                    data[i + 1] = gray;
                    data[i + 2] = gray;
                }

                // Put the desaturated image data back onto the canvas
                ctx.putImageData(imageData, 0, 0);

                // Get the resulting Base64 image data from the canvas
                const desaturatedBase64String = canvas.toDataURL('image/png');

                // Resolve the promise with the desaturated image data
                resolve(desaturatedBase64String);
            };


            img.onerror = function () {
                reject(new Error('Failed to load image'));
            };
        });
    }

    static invertBase64Image(base64String) {
        if (base64String && !base64String.startsWith("data:image/png;base64,")) {
            base64String = `data:image/png;base64,${base64String}`;
        }

        return new Promise((resolve, reject) => {
            // Create an Image object
            const img = new Image();
            img.src = base64String;

            img.onload = function () {
                // Get the canvas and its context
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                // Set canvas dimensions to match the image
                canvas.width = img.width;
                canvas.height = img.height;

                // Draw the image onto the canvas
                ctx.drawImage(img, 0, 0);

                // Get image data from the canvas
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const data = imageData.data;

                // Loop through each pixel and invert
                for (let i = 0; i < data.length; i += 4) {
                    data[i] = 255 - data[i];
                    data[i + 1] = 255 - data[i + 1];
                    data[i + 2] = 255 - data[i + 2];
                }

                // Put the desaturated image data back onto the canvas
                ctx.putImageData(imageData, 0, 0);

                // Get the resulting Base64 image data from the canvas
                const desaturatedBase64String = canvas.toDataURL('image/png');

                // Resolve the promise with the desaturated image data
                resolve(desaturatedBase64String);
            };


            img.onerror = function () {
                reject(new Error('Failed to load image'));
            };
        });
    }

    /**
     * Execute any function in a WebView.
     * @param {Object} options - Options for executing the function.
     * @param {Function} options.func - The function to execute.
     * @param {Object} options.context - An object instance to bind the function to for execution.
     * @param {Array} [options.args=[]] - Arguments to pass to the function.
     * @param {Array} [options.remote_scripts=[]] - Remote scripts to load.
     * @returns {Promise<any>} - A promise that resolves with the result of the function execution.
     */
    static async executeInWebView(options) {
        const {func, context = null, args = [], remote_scripts = []} = options;
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
            DebugLogger.error(`Reconstructed Error: ${error}`, true);
            throw error;
        }

        return resultObj.result;
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
            refresh_secs = 300
        } = options;

        this.callback = callback;
        this.tokenId = tokenId;
        this.auth_code = auth_code;
        this.tokens = tokens;
        this.refresh_secs = refresh_secs;

        Object.assign(this.configuration, configuration);
    }

    // Discover OIDC configuration
    async discoverOIDCConfig(realm = null) {
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

    async process_auth_callbacks(data, creds = {}) {
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
        let {oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        const headers = {
            "Accept-API-Version": "resource=2.1, protocol=1.0",
            "Content-Type": "application/json"
        }

        if (!oid_config.hasOwnProperty("authorization_endpoint")) {
            DebugLogger.error("No Authorization Endpoint found in OpenID Configuration.", true);
            DebugLogger.error(oid_config);
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
            } catch (error) {
                DebugLogger.error(error, true);
                DebugLogger.error(req);
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
            "decision": "allow",
            "csrf": options.auth_cookie.value,
        }

        let params_url = this.Utils.objectToQueryString(params);
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
            DebugLogger.error("No redirect url provided by server.", true)
            return
        }

        let redirect_query = this.Utils.parseQueryParams(req.response.headers.Location);

        if (!redirect_query.hasOwnProperty("code")) {
            DebugLogger.error("No authorization code provided by redirect url.", true);
            return
        }

        this.auth_code = redirect_query.code;

        return redirect_query.code;

    }

    async acquire_tokens(options = {}) {
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
        req.body = this.Utils.objectToQueryString(params);

        let tokens_payload = await req.loadJSON();

        if (req.response.statusCode !== 200) {
            throw new LoginError("Error acquiring tokens.");
        }

        tokens_payload.auth_code = authorization_code;

        this.tokens = await this.Utils.extract_tokens(tokens_payload, await this.fetch_jwt_keys(options), this.callback);

        return await this.refresh_tokens();
    }

    async fetch_jwt_keys(options = {}) {
        let {oid_config = null} = options;
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
            DebugLogger.error("No GUID found.", true)
            DebugLogger.error(JSON.stringify(this.tokens, undefined, 4));
        }
    }

    async get_user() {
        if (this.tokens && this.tokens.hasOwnProperty("id_token")) {
            return this.Utils.parseJwt(this.tokens.id_token, undefined, false);
        }

        return null;
    }

    async get_access_token() {
        await this.check_tokens();
        if (this.tokens && this.tokens.access_token) {
            return this.tokens.access_token;
        } else {
            DebugLogger.error("No access token found.", true)
            DebugLogger.error(JSON.stringify(this.tokens, undefined, 4));
        }
    }

    async check_tokens() {
        if (this.tokens && this.tokens.hasOwnProperty("expires_at")) {
            try {
                if (this.tokens.expires_at < Date.now()) {
                    DebugLogger.log("Token has expired. Refreshing tokens.", true);
                    return await this.refresh_tokens();

                } else if (this.refresh_secs > 0 && Date.now() > this.tokens.updated_at + this.refresh_secs * 1000) {
                    return await this.refresh_tokens();

                } else if (this.refresh_secs < 0 && Date.now() > this.tokens.expires_at + this.refresh_secs * 1000) {
                    return await this.refresh_tokens();

                } else if (this.refresh_secs === 0) {
                    return await this.refresh_tokens();

                }
            } catch (error) {
                DebugLogger.error(error, true);
                if (error.name === "LoginError") {
                    // console.log(this.tokenId);
                    if (this.tokenId) {
                        try {
                            return await this.acquire_tokens();
                        } catch (error) {
                            if (error.name === "LoginError") {
                                DebugLogger.log("Error acquiring tokens using saved session.", true)
                            }
                        }
                    }

                    // Clear tokens and auth code
                    this.tokens = null;
                    this.auth_code = null;

                    if (this.callback) {
                        DebugLogger.log("Clearing saved tokens.", true)
                        await this.callback(this.tokens);
                    }

                    throw new ExpiredTokenError("Token has expired.");
                }
            }

        } else {
            throw new NotLoggedInError("User is not logged in.");
        }

        return this.tokens;
    }

    get is_logged_in() {
        return this.tokens !== null && this.tokens.hasOwnProperty("access_token") && this.tokens.hasOwnProperty("refresh_token") && this.tokens.hasOwnProperty("id_token");
    }

    async refresh_tokens(options = {}) {
        const {oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();

        if (!this.tokens.hasOwnProperty("refresh_token")) {
            throw new NotLoggedInError("No refresh token found.")
        }

        // Request tokens
        const params = {
            "scope": "profile",
            "client_id": this.configuration.client_id,
            "grant_type": "refresh_token",
            "response_type": "token",
            "refresh_token": this.tokens.refresh_token,
        }

        let req = new Request(options.oid_config.token_endpoint)
        req.method = "POST"
        req.headers = {"Content-Type": "application/x-www-form-urlencoded"};
        req.body = this.Utils.objectToQueryString(params);

        let tokens_payload = await req.loadJSON();

        if (req.response.statusCode !== 200) {
            DebugLogger.error("Error refreshing tokens.", true)
            DebugLogger.error(JSON.stringify(tokens_payload, undefined, 4));
            throw new LoginError("Refresh token has expired.");

        } else {
            const jwt_keys = await this.fetch_jwt_keys(options);
            
            const old_refresh_token = this.tokens.refresh_token;

            // Merge tokens_payload with existing tokens
            tokens_payload = {...this.tokens, ...tokens_payload};

            this.tokens = await this.Utils.extract_tokens(tokens_payload, jwt_keys, this.callback);
            
            DebugLogger.log(`refresh_token updated: ${this.tokens.refresh_token !== old_refresh_token}`, true)

            return this.tokens;
        }
    }

    async logout(options = {}) {
        const {oid_config = null} = options;
        // Load or access the OpenID server configuration
        options.oid_config = oid_config || this.configuration.hasOwnProperty("openid_config") ? this.configuration.openid_config : await this.discoverOIDCConfig();


        const params = {
            "client_id": this.configuration.client_id,
            "redirect_uri": this.configuration.redirect_uri,
            "id_token_hint": this.tokens.id_token,
        }

        const url = `${options.oid_config.end_session_endpoint}?${this.Utils.objectToQueryString(params)}`;
        let req = new Request(url);
        req.method = "GET"
        req.headers = {Accepts: "application/json"}

        DebugLogger.log("Requesting Logout.")
        await req.load();
        DebugLogger.log("Done");

        this.tokens = null;
        this.auth_code = null;
        this.tokenId = null;
    }

    Utils = class {
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

        static async extract_tokens(tokens, jwt_keys, callback = null) {
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
                str += new Array(5 - pad).join('=');
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
                DebugLogger.error("Proper key entry or 'x5c' not found.", true);
            }
        }

        static async parseJwt(payload, jwks, verify = true) {
            let jwt_payloads = payload.split(".");
            try {
                let data = {
                    headers: JSON.parse(this.base64UrlDecode(jwt_payloads[0])),
                    jwt: JSON.parse(this.base64UrlDecode(jwt_payloads[1])),
                    signature: jwt_payloads[2]
                }

                if (!verify) {
                    return data.jwt;
                }

                let key = this.key_to_PEM(jwks.keys.find(key => key.kid === data.headers.kid));

                let verified = false;
                try {
                    verified = this.verifyJWT(payload, key);
                } catch (e) {
                    if (e instanceof ReferenceError) {
                        verified = await Utilities.executeInWebView({
                            func: this.verifyJWT,
                            context: this,
                            args: [payload, key],
                            remote_scripts: ["https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/11.1.0/jsrsasign-all-min.js"]
                        })

                    } else {
                        DebugLogger.error("Unknown exception", true)
                        DebugLogger.error(e.toString())
                    }
                }
                if (verified === true) {
                    return data.jwt;
                }

                DebugLogger.error("Could not verify the integrity of the authenticated session tokens from the provided JWT.", true)

            } catch (error) {
                DebugLogger.error(error, true)
                DebugLogger.error(JSON.stringify(jwt_payloads, undefined, 4))
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
                DebugLogger.error(`Error in verification: ${e.toString()}`, true);
            }
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
            this.device_id = this.Client_Utils.generateNewDeviceId();
        }

        return this.device_id;
    }

    Client_Utils = class {
        static generateRandomBigInt(hexDigits) {
            let hexString = '';
            for (let i = 0; i < hexDigits; i++) {
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
                    DebugLogger.error("Client is not authorized. Try logging in again.", true);
                }
            } catch (error) {
                DebugLogger.error(error, true);
                DebugLogger.error(req.response);
            }

            return req.response;
        }
    }

    async api_get(endpoint, options = {}) {
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

    async get_user_info() {
        let headers = {
            GUID: await this.auth.get_guid(),
            "X-BRAND": "S",
            "X-CHANNEL": "ONEAPP"
        }
        return await this.api_get("v4/account", {header: headers});
    }

    async get_notification_history() {
        let headers = {
            GUID: await this.auth.get_guid()
        }

        const response = await this.api_get("v2/notification/history", {header: headers});
        if (response.length > 0) {
            return response[0].notifications;
        }
    }

    poll_notifications(options = {}) {
        return new Promise((resolve, reject) => {
            let {vin, after, category, message_includes = '', interval = 3000, timeout = 30000} = options;
            let end = Date.now() + timeout;
            after = new Date(after);

            const poll_timer = new Timer();
            poll_timer.timeInterval = interval;
            poll_timer.repeats = true;

            const poll = () => {
                this.get_notification_history().then(notifications => {
                    if (notifications.length > 0) {
                        let filtered = notifications.filter(notification => notification.vin === vin &&
                            new Date(notification.notificationDate) > after &&
                            notification.category === category &&
                            notification.message.includes(message_includes));

                        if (filtered.length > 0) {
                            poll_timer.invalidate();
                            resolve(filtered[0]);
                        }
                    }
                });

                if (Date.now() > end) {
                    poll_timer.invalidate();
                    reject();
                }
            }

            poll_timer.schedule(poll);
        });
    }

    async get_user_picture() {
        const guid = await this.auth.get_guid();

        return await this.api_get(`oa21mm/v2/profile/picture/${guid}`);
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

    get last_engine_status_timestamp() {
        if (this.status_cache.last_engine_status && this.status_cache.last_engine_status.occurrenceDate) {
            return new Date(this.status_cache.last_engine_status.occurrenceDate);
        }
        return null
    }

    async verify_vin() {
        let vins = await this.client.get_user_vehicle_list.map(function (vehicle) {
            return vehicle.vin;
        })
        return this.vehicle_data.vin in vins;


    }

    async remote_request(command, options = {}) {
        const initiated = Date.now();

        const {json = {}} = options;

        let result = await this.client.api_post("v1/global/remote/command", {
            json: {"command": command, ...json},
            header: {"VIN": this.vehicle_data.vin}
        });

        // Clear cached status
        this.status_cache.last_status = null;
        this.status_cache.last_ev_status = null;

        if (options.callback) {
            this.client.poll_notifications({
                vin: this.vehicle_data.vin,
                after: initiated,
                category: "RemoteCommand",
                message_includes: options.message_includes
            }).then(async result => {
                await options.callback(result);
            });
        }

        return result.returnCode === "000000" ? result : false;
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
            DebugLogger.error("Error refreshing vehicle status.", true)
            DebugLogger.error(result)
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
            DebugLogger.error("Error refreshing EV status.", true);
            DebugLogger.error(result_electric);
        }
    }

    async remote_door_lock(options = {}) {
        if (options.callback) {
            options.message_includes = "[DL1]";
        }

        return await this.remote_request("door-lock", options);
    }

    async remote_door_unlock(options = {}) {
        if (options.callback) {
            options.message_includes = "[DL0]";
        }

        return await this.remote_request("door-unlock", options);
    }

    async remote_trunk_lock(options = {}) {
        if (options.callback) {
            options.message_includes = "hatch lock";
        }
        options.json = {doorLock: {target: 1}}

        return await this.remote_request("door-lock", options);
    }

    async remote_trunk_unlock(options = {}) {
        if (options.callback) {
            options.message_includes = "hatch unlock";
        }
        options.json = {doorLock: {target: 1}}

        return await this.remote_request("door-unlock", options);
    }

    async remote_engine_start(options = {}) {
        if (options.callback) {
            options.message_includes = "[RES2]";
        }

        return await this.remote_request("engine-start", options);
    }

    async remote_engine_stop(options = {}) {
        if (options.callback) {
            options.message_includes = "[RES0]";
        }

        return await this.remote_request("engine-stop", options);
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
            if ((now - this.last_status_timestamp) > this.client.configuration.refresh_interval) {
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

    async get_engine_status() {
        let status;

        if (this.status_cache.last_engine_status && (Date.now() - this.status_cache.last_engine_status.cached_at < this.client.configuration.cache_interval)) {
            status = this.status_cache.last_engine_status;
        } else {
            status = await this.client.api_get("v1/global/remote/engine-status", {header: {"VIN": this.vehicle_data.vin}});
            this.status_cache.last_engine_status = status;
            this.status_cache.last_engine_status.cached_at = Date.now();
        }
        if (status.occurrenceDate) {
            let now = new Date();
            if ((now - this.last_engine_status_timestamp) > this.client.configuration.refresh_interval) {
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
            if ((now - this.last_ev_timestamp) > this.client.configuration.refresh_interval) {
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

    async get_status() {
        let status = new VehicleStatus(this)
        await status.init();

        return status;
    }

    async get_charge_info(property) {
        let ev_status = await this.get_electric_status();

        if (ev_status.vehicleInfo && ev_status.vehicleInfo.chargeInfo) {
            if (!property) {
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
        const {
            auth = new ToybaruAuth({tokenId: options.tokenId, callback: this.save_tokens}),
            client = null,
            vehicle = null
        } = options;

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
                DebugLogger.error(error, true);
                if (["NotLoggedInError", "ExpiredTokenError"].includes(error.name)) {
                    DebugLogger.error("User is not logged in.", true);
                }
            }

            // if (config.runsInApp && !this.client.auth.is_logged_in) {
            //     console.log(this.is_logged_in)
            //     await this.launch_app();
            // }
        }

        this.save_prefs();
    }

    async load_tokens() {
        let tokens = {}
        if (Keychain.contains("subaru_tokens")) {
            tokens = JSON.parse(Keychain.get("subaru_tokens"))

            this.client.auth.tokens = tokens;

            if (tokens && tokens.auth_code) {
                this.client.auth.auth_code = tokens.auth_code;
            }

            try {
                await this.client.auth.check_tokens();
                await this.client.auth.refresh_tokens();
            } catch (e) {

            }
        }
    }

    save_tokens(tokens = null) {
        if (!tokens) {
            Keychain.remove("subaru_tokens");
            return
        }

        Keychain.set("subaru_tokens", JSON.stringify(tokens))
        DebugLogger.log("Tokens Saved", true)
    }

    save_prefs() {
        this._prefs.device_id = this.client.get_device_id();
        if (this.vehicle && this._prefs.vehicle) {
            this._prefs.vehicle.status_cache = this.vehicle.status_cache;
        }

        Keychain.set("subaru_connect_prefs", JSON.stringify(this._prefs));
    }

    load_prefs() {
        if (Keychain.contains("subaru_connect_prefs")) {
            this._prefs = JSON.parse(Keychain.get("subaru_connect_prefs"));
            this.client.device_id = this._prefs.device_id ? this._prefs.device_id : this.client.get_device_id();

            if (!this._prefs.vehicle || !this._prefs.vehicle.vin) {
                this._prefs.vehicle = null;
            }
        }
    }

    fetch_customizations() {
        return {
            descriptions: {
                refresh_interval: {
                    label: "Refresh Interval",
                    description: "The time in minutes to wait before refreshing the vehicle status.",
                    type: "number"
                },
                widget_color: {
                    label: "Widget Color",
                    description: "Select a background color for the widget.",
                    type: "color"
                },
                nightshift_widget_color: {
                    label: "Nightshift Widget Color",
                    description: "Select a background color for the widget when in Nightshift mode.",
                    type: "color"
                },
                lockscreen_widget_background: {
                    label: "Lockscreen Widget Background",
                    description: "Enable a visible background for the lockscreen widgets.",
                    type: "boolean"
                },
            },
            values: {
                refresh_interval: (this._prefs.refresh_interval || this.client.configuration.refresh_interval),
                widget_color: this._prefs.widget_color || "#01478E",
                nightshift_widget_color: this._prefs.nightshift_widget_color_widget_color || "#00203e",
                lockscreen_widget_background: this._prefs.lockscreen_widget_background || false
            }
        }
    }

    update_customizations(customizations) {
        this._prefs = {...this._prefs, ...customizations.values};
        this.save_prefs();
    }

    get is_logged_in() {
        return this.client.auth.is_logged_in;
    }

    async launch_app(delay = 500) {

        // Set the use_embeded_app value to false if you want to use the SolteraConnectApp.html file in  iCloud Drive instead.
        const use_embeded_app = false;

        let path;
        if (use_embeded_app) {
            path = '';
        } else {
            let fm = FileManager.iCloud();
            path = fm.joinPath(fm.documentsDirectory(), "SolterraConnectApp.html")
        }

        let url = `file://${path}`;

        let wv = new WebView();
        wv.shouldAllowRequest = request => {
            const data_request = request.url.split("#data_request")[1];
            if (data_request) {
                const data = this.client.auth.Utils.parseQueryParams(data_request);
                // console.log(data);
                if (data.login && data.tokenId) {
                    this.client.auth.tokenId = data.tokenId;
                    this.client.auth.acquire_tokens().then(async (result) => {
                        const message = {
                            type: "user",
                            value: await this.client.auth.get_user()
                        }
                        wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`).then(() => {
                            if (!this._prefs.vehicle) {
                                const message = {
                                    type: "navigate",
                                    value: "vehicle_select"
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`)
                                // console.log("Navigating to vehicle select.")
                            }
                        });
                    });
                }

                if (data.get_vehicle_status && this._prefs.vehicle) {
                    this.vehicle.get_status().then(status => {
                        const message = {
                            type: "vehicle_status",
                            value: status.get_status_values()
                        }
                        // console.log(JSON.stringify(message.value, undefined, 2));
                        wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)});`);
                    });
                }

                if (data.get_vehicle_list) {
                    this.client.get_user_vehicle_list().then(vehicles => {
                        const message = {
                            type: "vehicle_list",
                            value: vehicles
                        }
                        wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                    });

                }

                if (data.fetch_customizations) {
                    const customizations = this.fetch_customizations();
                    const message = {
                        type: "customizations",
                        value: customizations
                    }

                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                }

                if (data.selected_vehicle) {
                    this.client.get_user_vehicle_list().then(vehicles => {
                        const vehicle = vehicles.find(vehicle => vehicle.vin === data.selected_vehicle);
                        this.vehicle = new ToybaruClientVehicle(this.client, vehicle);
                        this._prefs.vehicle = vehicle;
                        this.save_prefs();

                        this.vehicle.get_status().then(status => {
                            const message = {
                                type: "vehicle_status",
                                value: status.get_status_values()
                            }
                            wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                        });
                    })
                }

                if (data.lock_doors) {
                    this.vehicle.remote_door_lock({
                        callback:
                            (result) => {
                                const message = {
                                    type: "lock_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.climate_on) {
                    this.vehicle.remote_engine_start({
                        callback:
                            (result) => {
                                const message = {
                                    type: "climate_on_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.climate_off) {
                    this.vehicle.remote_engine_stop({
                        callback:
                            (result) => {
                                const message = {
                                    type: "climate_off_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.unlock_doors) {
                    this.vehicle.remote_door_unlock({
                        callback:
                            (result) => {
                                const message = {
                                    type: "unlock_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.lock_liftgate) {
                    this.vehicle.remote_trunk_lock({
                        callback:
                            (result) => {
                                const message = {
                                    type: "liftgate_lock_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.unlock_liftgate) {
                    this.vehicle.remote_trunk_unlock({
                        callback:
                            (result) => {
                                const message = {
                                    type: "liftgate_unlock_success",
                                    value: result
                                }
                                wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);

                                this.vehicle.get_status().then(status => {
                                    const message = {
                                        type: "vehicle_status",
                                        value: status.get_status_values()
                                    }
                                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                                });
                            }
                    });
                }

                if (data.logout) {
                    this.client.auth.logout();
                    this.save_tokens();
                    this._prefs.vehicle = null;
                    this.save_prefs();
                    const message = {
                        type: "user",
                        value: {}
                    }
                    wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                }
            }

            const customize = request.url.split("#customize")[1];
            if (customize) {
                const data = this.client.auth.Utils.parseQueryParams(customize);

                // check if any of the data is a boolean that got parsed as a string
                for (let key in data) {
                    if (data[key] === "true") {
                        data[key] = true;
                    } else if (data[key] === "false") {
                        data[key] = false;
                    }
                }

                this._prefs = {...this._prefs, ...data};
                this.save_prefs();

            }
            return true;
        }

        if (use_embeded_app) {
            await wv.loadHTML(WebApp.toRawString(), url);
        } else {
            await wv.loadFile(path);
        }

        if (this.is_logged_in) {
            const message = {
                type: "user",
                value: await this.client.auth.get_user()
            }
            message.value.profile_picture = await this.client.get_user_picture();
            await wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
        }

        if (delay > 0) {
            Timer.schedule(delay, false, async () => {
                if (this.is_logged_in && !this._prefs.vehicle) {
                    const message = {
                        type: "navigate",
                        value: "vehicle_select"
                    }
                    await wv.evaluateJavaScript(`window.onScriptableMessage(${JSON.stringify(message)})`);
                }

                await wv.present(true);
            });

        } else {
            await wv.present(true);
        }

    }

    async select_vehicle() {
        let selected_vehicle = {}
        const vehicles = await this.client.get_user_vehicle_list();

        // Create a table
        let table = new UITable();

        // Create a header row
        let headerRow = new UITableRow();
        headerRow.isHeader = true;
        headerRow.addText("Select Vehicle");
        table.addRow(headerRow);

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

class VehicleStatus {
    _vehicle_status;
    _ev_status;

    constructor(vehicle) {
        this._vehicle = vehicle;
    }

    async update() {
        this._vehicle_status = await this._vehicle.get_vehicle_status();
        this._engine_status = await this._vehicle.get_engine_status();
        this._ev_status = await this._vehicle.get_electric_status();
    }

    async init() {
        if (!this._vehicle_status || !this._ev_status) {
            await this.update();
        }
    }

    check_values(category_name, section_name, value_name, compare_to) {
        return this._vehicle_status.vehicleStatus.some(category => category.category.includes(category_name) && category.sections.some(section => section.section === section_name && section.values.some(value => value.value.includes(value_name) && value.status === compare_to)));
    }

    some_properties(properties) {
        return properties.some(property => this[property]);
    }

    get vin() {
        return this._vehicle.vehicle_data.vin;
    }

    get modelYear() {
        return this._vehicle.vehicle_data.modelYear;
    }

    get modelName() {
        return this._vehicle.vehicle_data.modelDescription;
    }

    get odometer() {
        return `${this._vehicle_status.telemetry.odo.value} ${this._vehicle_status.telemetry.odo.unit}(s)`;
    }

    get value() {
        return this._ev_status.vehicleInfo.chargeInfo.chargeRemainingAmount;
    }

    get door_unlocked() {
        return this.some_properties(["door_d_f_unlocked", "door_d_r_unlocked", "door_p_f_unlocked", "door_p_r_unlocked"]);
    }

    get engine_status() {
        return this._engine_status.status;
    }

    get engine_duration() {
        return this._engine_status.timer;
    }

    get engine_start_time() {
        return this._engine_status.date;
    }

    get door_d_f_unlocked() {
        return this.check_values("Driver Side", "Front Door", "Unlocked", 1);
    }

    get door_d_r_unlocked() {
        return this.check_values("Driver Side", "Rear Door", "Unlocked", 1);
    }

    get door_p_f_unlocked() {
        return this.check_values("Passenger Side", "Front Door", "Unlocked", 1);
    }

    get door_p_r_unlocked() {
        return this.check_values("Passenger Side", "Rear Door", "Unlocked", 1);
    }

    get door_open() {
        return this.some_properties(["door_d_f_open", "door_d_r_open", "door_p_f_open", "door_p_r_open"]);
    }

    get door_d_f_open() {
        return this.check_values("Driver Side", "Front Door", "Closed", 1);
    }

    get door_d_r_open() {
        return this.check_values("Driver Side", "Rear Door", "Closed", 1);
    }

    get door_p_f_open() {
        return this.check_values("Passenger Side", "Front Door", "Closed", 1);
    }

    get door_p_r_open() {
        return this.check_values("Passenger Side", "Rear Door", "Closed", 1);
    }

    get liftgate_open() {
        return this.check_values("Other", "Hatch", "Closed", 1);
    }

    get window_open() {
        return this.some_properties(["window_d_f_open", "window_d_r_open", "window_p_f_open", "window_p_r_open"]);
    }

    get window_d_f_open() {
        return this.check_values("Driver Side", "Front Window", "Closed", 1);
    }

    get window_d_r_open() {
        return this.check_values("Driver Side", "Rear Window", "Closed", 1)
    }

    get window_p_f_open() {
        return this.check_values("Passenger Side", "Front Window", "Closed", 1);
    }

    get window_p_r_open() {
        return this.check_values("Passenger Side", "Rear Window", "Closed", 1);
    }

    get window_f_open() {
        this.some_properties(["window_d_f_open", "window_p_f_open"]);
    }

    get window_r_open() {
        this.some_properties(["window_d_r_open", "window_p_r_open"]);
    }

    get blower_on() {
        return this.engine_status === "1" && this._ev_status.vehicleInfo.remoteHvacInfo.blowerStatus === 1;
    }

    get plugged_in() {
        return this._ev_status.vehicleInfo.chargeInfo.connectorStatus > 2;
    }

    get charging() {
        return ![12, 45].includes(this._ev_status.vehicleInfo.chargeInfo.plugStatus);
    }

    get remainingChargeTime() {
        return new Date(Date.now() + this._ev_status.vehicleInfo.chargeInfo.remainingChargeTime * 60000);
    }

    get remainingChargeTimeDescription() {
        return `${getTimeDifferenceDescription(this.remainingChargeTime)} left`;
    }

    get remainingDistance() {
        return `${this._ev_status.vehicleInfo.chargeInfo.evDistanceAC} ${this._ev_status.vehicleInfo.chargeInfo.evDistanceUnit}`;
    }

    get remainingDistanceClimateOff() {
        return `${this._ev_status.vehicleInfo.chargeInfo.evDistance} ${this._ev_status.vehicleInfo.chargeInfo.evDistanceUnit}`;
    }

    get nickName() {
        return this._vehicle.vehicle_data.nickName;
    }

    get lastUpdated() {
        return new Date(this._vehicle.last_ev_timestamp);
    }

    get lastUpdatedDescription() {
        return getTimeDifferenceDescription(this.lastUpdated);
    }

    get_status_values() {
        let descriptors = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(this));
        let getterFunctionNames = Object.keys(descriptors).filter(name => !descriptors[name].writeable);

        let status_values = {};
        for (let name of getterFunctionNames) {
            status_values[name] = this[name];
        }

        return status_values;
    }
}

function getWidgetTextColor(options) {
    if (options.backgroundColor) {
        if (Utilities.hexColorBrightness(options.backgroundColor.hex) <= 0.5) {
            return Color.white();
        }
    }

    return Color.black();
}

function setWidgetBackground(widget, options = {}) {
    if (options.backgroundColor) {
        let color1 = options.backgroundColor;
        let color2 = options.backgroundColorGradient || options.backgroundColor;

        let gradient = new LinearGradient();
        gradient.colors = [color1, color2];
        gradient.locations = [0, 1];
        widget.backgroundGradient = gradient;

        widget.backgroundColor = Color.clear(); //new Color(options.backgroundColor);
        widget.addAccessoryWidgetBackground = true;
    }

    return widget;
}

async function createSmallWidget(options = {}) {
    let widget = new ListWidget();
    widget.setPadding(8, 10, 10, 10);

    setWidgetBackground(widget, options);

    let stack = widget.addStack();
    stack.layoutVertically();
    stack.setPadding(0, 0, 0, 0);

    let header = stack.addStack();
    header.layoutHorizontally();
    header.spacing = 10;
    header.topAlignContent();
    header.size = new Size(0, 25);

    let header_logo = header.addImage(Image.fromData(Data.fromBase64String("iVBORw0KGgoAAAANSUhEUgAAAOEAAAB5CAYAAADPhkZUAAAeF0lEQVR4nO2dd7glVZXof5ugRMk0dIBumgwqIIigjGIOOPr5cAyj4DPM+MyOw4xxzI4zOqYZ9XM+faZxFMMz64hiQIICTZLU0kBD0zln6MDv/bHqcG7fPvdUnXOqTp1z7/19X30nVu21q2rV3nvtvdZKTNJ31H2AvYEDgP2BRwAHAQdm7w8c8f0+2ese2SvZd3sAjjp0ArYA67L364D7gbXApuzzGmBl9n519n5N9p81wIaU0vqSqzxJG1LdAow31N2Aw7JtJjAdmAVMBaYRynYwoUgPq0fKMdkKbABWAKuA+4BFwHxgAXAPsBhYklLaWpOM445JJewSdQ/gSGA2cAJwXPb+SGAKoWTjkY3AUkIh7wRuz7Z5wD0ppftrlG0omVTCAqj7AscAj862RxEKNxXYrUbRBoltRKt5J/An4HrgJuDPKaUNdQo26Ewq4SjUBBwNnAqcmb0eDxxep1xDzCLgNuA64Grg+pTSnfWKNFhMKiGgHg88HngCcAZwLLB7rUKNXx4A5hIKeRlw5URXygmphOo04CzgXELxTqTebuUWYDOwfsTWsGZuyrbN2badMJ6Mde0E9iIeIg8H9sw+701YV/eiaXHdN/v94RXUqSgPALcAlwO/Bq5KKS2rUZ6+M2GUUD0FeCrwLKK127dPRa8lLI0LCYPGvcASwsq4lJgmWJX9bzOwOaX0YJUCZV3uPbNtP2JK5ADCoHQ4Ydk9InttWHQf0fJg5bMKuBL4H+DXKaXb+lRubYxbJVR3BR4HnEco3qMrLG4zTVP+XUR3606aJv1VKaUtFZZfGerDCCU8nJhqOYrors8mpmCmUl1Luh24BvgJ8POU0nUVlVMr404J1bOB5xHKd2IFRawA7iC6UDcBt2afF6WUtlVQ3sCSKeg0wnJ8EvGgO5lQ1AMqKHIO8H3ghymlmys4fi2MCyVUjwPOz7ZTSjz0ZqJVu454It9AmNxXlVjGuEM9hLAonwY8lrAwH015xq7twBXAtwiFXFTScWthaJUwm7s7D7gAeDLlrD5ZT8xxXUVc5OtSSvcUkGUmsCyltKkEGcYd6i6EEp5OWKHPInopZXRjVwM/Bb4G/CqlNHop3yRlo56k/qt6j72zTb1e/ZT6PHVqF/IcqK5VP1pFfccr6mz1AvWr6l0lXEuza/lmdUrd9RuXqM9Uv69u6fFCrVR/pL5BPakEuc7LjvuHMuo5EVH3UM9S361eXsI1Xq5+Vq3SGDcxyC7OK9Q/9nhRFqtfU1+kHlqyjP+WlbFWPbjMY09U1GPV16uXqJt7uO7b1e+pT6q7TkOHuo/6RvW2Hi7ASvW/1ReoVVjqGrJeO6LMZ1RVzkRFnaW+Sf2dMXzolkvUZ9ddn4FH3ctQvnldnuit6i/VV1pyizeGvEeq948o/8NVlzmRUR+lflC9tcv7Q/U36tPrrsvAoe6uvtbulW+e+iH15D7L/bJRclzWz/InKtn98hz1YnVDl/fMT9Un1F2XgUD9X4ZVqxv+Rz1f3bMm2b8ySp61xhzZJH3C6K6+V72zy3vo6+qxddejFtQz1J93cdI2qF9SH1uz/LuNceHPq1OuiYq6t90b8dar71P3rrsefcGYV/uEnQ+yVxjzg0fVXQcA9fQx5Px03bJNdNTnqpd2oYy3qy+oW/5KUV+s3t3hiVliPKU6nkivEvUdY8h7Y92yTRKoT7W73tY31SPqlr9U1OnGILoTVhnGloEcYxlWtlZsdaKOMQYU9eltrtdYLFdfXbfspaD+tTFZXpStxmqHI+uWfSzUQ41xxFj8bd0yTrIzxmKNmztUxu+oh9Ute1eoj1C/2GGFf6I+pm7Z8zAWALTjB3XLOElr1IerFxk9raLcqz6nbtk7wrB8dvLE+bP6orrlLor6hZz6rFT3r1vOScZGnan+Vwf3qOoH6pa7EOpr7Gy938fVfoVO6BljaqLIooK/rFvWSfJRn280AkX5qQNqp0BN6r93UJnr1XPqlrtTjFa+CP+3blknKYa6n/q5Du7dP6un1S33DqgHqD/roBKfsKZVLr2ifrhgHRere9Ut7yTFMVrFBQWv71oHZWGG0be+oaDgC9Xn1S1ztxitfSeLh59bt8yTdIY6zehyFmG7+qq6BX6kxSfff63OqFXgHlHP7kABVb9dt8yTdIf6/g6u89vqEvJ0YzVLET5txBkZaux8ymWDk6EWKsMYBlW2MMJwLlhb8Fq/uyo5xhLuFIvPs7yhr8JVhHqwuqZDJVT9h7plH68YC/k3GvkeqyrjNIt7aLyrKjlGC3WCxVbAbFSf3xeh+oDhLtMN8400apOUiDFV1Aj29cSKy5quzil4vV9fpSyoUy0WGWu1Qzj9MBZZvVd3pHo78k9112G84Y5eLO/rQ3n7GyE2ivBXVQmxtzvGUxmLJerplQhRE3Y2/dKKB9Qz6q7HeEJ9+4jze0WfytzDCJ+Sx/1GJPjSBfhugcJXOf4U8NMdKtxY3KvOrrs+4wX1t6Nu+r4s+DfiIF1R4HovVMvLaWnEg8xjs+OrC3qgEfqgTBaoT6m7bsOOMTzYNOrc9s3tyOia3lTgev/WyIDVc4HnFrzBxoVHsnqQ+jo7dz7uhC+pj6q7rsOKemGLc/rDPstwpMUMlL1F4DM0/t4CBf19SXXrO+rD1OPVlxst39IC9S2DbcZA/z2GB/i0us/FsGDrFS3r7EOYy1FyPN4Y7+fRtofYtqlUvwJcmCPLN1NKL+1Q/lrILtJRRCqvRxLpvI4j8uztWp9kQGTfnU/kNbw92+Zn2/KU0sa6BBsk1KOJtHStEgBdlFL6eJ/leR3w2Zy/zQVOSSnd3+rHMZVQfRpwSc7B7wBOHaQbRN2PyDg7i1CuYwmlOwqYTmSmHSYeAJbRTEK6gFDU+4isvyuAFcOahLRTjG7nWG5iK4AzU0p39VEk1G8Bef6wH04ptVxV01IJ1d2BG4ET2hz0QeCclNKVRQQtC8Mz4RBC0Y4gFGs2MINQuinAocDQL5MryHri5ltKKOZCmhmCFwDLCSVeV3Ua7ipRjwE+ALw45693AX+bUvpV9VIF6oFESr12wcjuBx6VUrpj9A9jKeGbgLzQfR9PKV1UVNAiGHEfGy3ZoUQW2KmEok0ncqgfRuRYH0pXqBrYRuTwW0Uo6FJCSRcRLWlDeVemlDbXJWQDY43xwcQDdibREJwFPInOrvmVwGVEdt+5wD0ppXVlyjoSwzD5vZy/fSeltNNE/k5KmHXn5hKKMBbzgZM6SYppJPXcPzvuYUQO9COy9zOI1u3Q7D+VrQWcpCWbiBaz0XrOB+7O3jcUd9VYY5pOUR9OKNpU4EhiqDCL6NFMy7ayhw1LiYfO3UR3fl72eT4x5l7bawHqj4A897XHppSuGflFKyX8B+Bfcg70kpTSt0bt11CmRot1BKFo02i2XgcCk+soh4+NRJd2JaGUi2l2fZcR3eF1RJcLwsi1F3AQzYfuTOJ+mEk8bKdk/6mbbYT8S4gewr2Egi7IPt+TUlpZ5EBG2vabaJ81+nsppfNHfrGDEhoLjW8nnk5jMSeltMOqGCOo0d1EKzbJJOOJO4he39Yif1a/CLRz9N0GnJxSmtv4YrdRf/hL2isgwIdafLcBeAvRf59Oc0x3CPAIYGLE+J8YbADWEt3XFdm2Mvtu+4j/7UN0ORvDjCnAAQxG6zcWm2i29ouIhuXaogqY8VHg5YzdGu4GvBp4yJ4yuiW8BHhamwJuI7S4kJUtM7QcSLNbMo2mVbMxLjyEuDiVJfKcpBDbCUVaQ7N7tpzonjXGio3vVndiD4CHrNoHEwo5nabh5QiaQ5cpwO69V6UtG2l2Pe8h7B/zCYVbTIwPexr7qhcD7TwpFgJHN8p5SAmNBbBzgYe32fnvUkqf7EXA0ai7EYp6AHERDs+2I2kabRpK/Ajqn1QfVjYR47flNA0u89lxbLcaWJNS2tZv4TIlPYy47rOJRRTHE/O8s+nuut8N3ArcnL3eQdR3cZV1NNJz/ybnb89MKf0CdlTC1wP/0WanzcAxKaWFvQrZKZnZutGiNgw/RxEt6yyainsAE1dJ1xNdqYbRZD7RijWmI5YQFs7apyE6Qd2VUMQXAG+nmOX8u8AngevKsuh2Qna/3ko8SMbiCyml18KOSvgToF2o70tSSgObkz0zDh1OKOlRRFfnGOLJOoP2Uy7DwIM0pxEapvb5xOT0IqI1W13HTdcv1LOAX9LexvCxlFLtIUXUjwHt1lTfAZyQUtqesh32IeZO2i2AfWNKqV1LObAYEb6nEcp5LPGEOo5oRWcwWKtr1hAKNY+4JndkrwuARVVOOA8DRij694zx8w0ppVP7Kc9YqOcCv27zlweJFTS3NHY4M2cV+HbHoeuNuqfhQfFX6uftPuVyL1yflf0q9XEOSXQ2dRd1Vg3lTnNnX8IGf9NvecZC3ddIr9aOC0fu8OqcP99rrHIY1xjhC16g/r6I9vTAQvWD6sl117lb1JcZjtyn1FD2JS3O6SYHzB3M/JyIn4RmN6zdQm2AuSmlB6oVuX5SSvenlP5fSukc4A2EMapsPg88OqX0npTSzRUcv188n1j99Owayv5Ri++ursNomMNNOb8fC00lnJnz53m9SjNspJQ+CzyTmDsrizenlF6XUlpR4jH7jjGd8Pjs41NrEOFSdlwYAPDzIjsaqbAvLl+kluzkMTGK6Q+9Uy/PaTbfWa2sg4sR3mNL0X5mGz5Sd13KQv2LEfVab5/HsUZOkFtGnd/cAGNGpIitho3joD7I+fyce+I+dc9GS5g397K8aoEHlZTSb4De4oREt6S/YdKrZeRU1T7Ak/tZeEpJYGSYw3vJ7/oBnE0sG9uFcI+qmrwez17AvrsYk6F5ng0Twmu7DR8l5uW65T3D7FDbgmeN+lxHKunLR7y/umBkgZFy96MbnbfmdFdg112yN1Wv1xtqMqNUnpPzWNwK/LhEcWpFPZ6IzzOSJ9v/fJPX0hwX/iHvz0bowZGK93TLCEfYGwLukj1B8hbj1i3sIPANwmeuU76SdZ/GCy9kZ++bw4F+x1OdRyxqgPCez+M0Yi1qg4bHfpUUWgTS+FPeUqcJ7yeYWTR/2eFuW4h1jOMCY7H9K8f4+bX9lCVrPBoBnW4tsEsruaue3N835/cHgM0NJVyV8+fDepdnXJAXQ2Q016aUehlLDhrvZOzprOeoY0VBq4qPAe9OKS1r9yd1OnBBi59eaLXh8/PC4K8jFt4XSn75rfbHmhiohxmJP4syLiyixhKs9xSo7wZj+d3AeLKoj1AvbSPz79RKfFnVD+Scr8ug2bfPm4yvLBvqMJFSWqLOAf6i4C6XVilPVWQ35VGEAeZs4OnkR1yA8G74IvBW9efAVURX8d5OnYB7wTASHUNcpzfQ3qXoL4Br1M8QPoB3lijriTm/3wVNJfxTzp+PUQ9LKS3pWazh51KKKeEi4IaKZekKw+3rAJrRDRoxW2fRdP3qZTL7pGyDsGAuUu8knMZvBf5M5oKVUtrQQzmoDyNkPxE4FXgMcDLFHhoNZtO0fi9Q542Q9Y5M1sUppfUdyLUrkOf08CfYUQkfYGyv+n0I69LPigoxjvltwf9dXZcDrRHufwqhTNNohpGYQbirNSLf9WNqates3BlE7NAG24HF6kKaLlt3ES5bS4nx0kYiMNIuRCu7f3acWTTd0Y4j6jbaYtstDVnPHSXrUnVRJuN84kEyP5P3nhZrq48lehPt2NGqq96Q03/9VLe1Gk9YzEVF9a01yfePBWQbFrYZCVe21i1IDvc4alypvj5nn5VGj2SHp8fvgEe3ub7PUt+WUhq9cHZCkVJar15HjJPacXnO71VxFfBVogVsRLzbn+GIWL6KiHOzhHBuXkNz1cmeROs9JdsOorzWr1MeIJakLc62Oew81/68nGP8MaW0BnasxA+BN7XZ6VhikP77TqQdp/ye9kq4iAgu1HdSSpcR4d+Bh6ImNEIPTiNW7s8kxkyNYFqH0j7AV5mspJncZj7RFb2LZv6M1XlBmIxICY1AwicRBqSTgaMpd057GdHdbIwR78rkXQQsHSsRkjqTfLvBQ6uoRirh5cSJaDegfRWTSgg7Lh5uxZxBCaiUGT4aadeuGf274ZbUCEM4k7iRZ7FjIK1uuZtILHQj8VC6A1jYqytXFuJjHaEYv2h8b3hznAicDpxJuFsVneNeQSyFu45YDN7IX7G6CxEvoP1D7X7gJy1/UT+W049db5l5uIcUI5X26jbn6R/rlrEMjEgDj1T/SV2Tc280WK5+RD3dmqMxZNfpvQVkfp8lJRjNzlleYt3WCpgd4HjzB8EfLEPYYUe9rM05emLd8pWNeqLh/9aOP6hH1C3raNT3t5G51AUV6t/knCPNW1mk/ijnAKvsc1riQUT91zbnZ1xGE1ef3ea+WO2AxXhpYLROi1rIfJ+Ri7PMcu7O0Z/bzFtRpJ6VcxDVoQx9WCZGQKhWXJa/9/BitHat+EzdsrVD/VwLmf+z5DLeXkB3/nfRg/0s50BbrSHK1iChzjLmsEbziT6U/Vr1XVWXM0bZfz/GPfGEOuQpiq1b8bxphE6OP0Ndl6M3cy3a8qqnGHE42pFnIRzXGHE357Y4Ly+suNxd1WVZWXmuMlWU/9gWdV5sB069RoyY04xw8X3BnY1pa9WDSzx+3jBONS/V904H/XyBg9YebrxO1ItHnY8tRm71Kss8bUR5/XakbQRMHm2g+UGHx3hatl9fwyWqvx0hc17Clk6O+8oCuvK7sfZv9yR6B7FyoR0fVs/sSvLxwbWjPi+gt1g0RXjmiPd9zw2SzX/+cdTXnY6DG3Xod8zSkXKWooRGuI+80CdbCW+Orgo4v4CG3+k4tQbmoT5l1LloFZS27DJ/N6K8Wrw01DeNqndHYSLUOdl+t9rfLumTR8jcc4Q4o1dwYwEdGSt3RuGCvlygkAnpXeHOTr7vr7i8w9WNI8rbZjyJ+4o7WtCX2cHYVJ1p06C13T6mAlAPMkL3P2AJ40H12wV044/26uSs7qPeXqCwz/ZaqWHEHZ+Ez6+4rJe3OO8X5e9Zuhz7qSuy8ttlHmq17+jx0xurknOM8m9RbynhOB8toBPrLMtGYFhLN+YUqPreUgocItSvZ3XfqlYagcDWFrirqyyzjSyNbvHHOtxvdB06DZ7VE+pxvV4n9aICuqBlW8rVFxUs+C2lFjzgqG/N6j3f8PKuqpwjjK5UKx5bVblt5Pl4pzearWP0PKAeXaWsZaK+paAeVLO8U31nQQH+rhIBBhCbg/2OumVdlPOlNue778GF1ceoP7WDJYyOHSzq81XKWhYWV8BvVi3IfxQUpDeL0JBgDPbXqO+rsIwLC5zvvsb97BT1UcYEeSu2qOfULWM71HcUvO9/ZYnrUdsJ9NWCAg30esKyMJYsle62o56g/lvBc6367+pJ+UfuH4YR50J1SY7sa9Q3OICucuonC57/Kw2H447oOry9+g3gpQX++gPgwomea70dRpfuMMKR9njCW/zRhINqp+bt7cAthGPqnURAonlkAZSqTExjONXOIurwSJoe750o1lpC9puzbR7NaGctPdmrwph6+RqREDWP64GnpZRWdlpOTzkm1C8Dryjw1xuAl6WUejYNDxuG5/ohRHyUw2mGGGxEP5tGKGDVCx7WE2EZ7sq2RriG+TTDSuTmzDCMT1MIT/xjCIU7Lns/g2pSJmwjVm8tIlYk3UM8YO7LthXAqpRSXjqHwqgnEvlHijgqXAmc16UXfu+JXowobG8u8Nc1wGtTSv3KktpXspvzRUQMyyOIG3UqoYAHELnoBpUVRA7K+4i4KkuJgEtbiLR5B9OMUTqdqNPetUjamvXE/bWckH058WD5ejcPfvUlwOco9kC5BDi/k5iklaC+q4Nxy6fUvHyIQ4cxLpxksHhNh9dwT/UzHRz/v4wkOT1RWsoz9a+B/6TYE38O8PqU0uiFwEONehTREs4gWsEjiCBK04ju6EHAfrUJuDOriJbjHiLb7Tyi27eEaAkb4S0bXdDDiXFrY5tKfcmCNhEt3gpC9oVE9/o+oj5LUkr3Fj2Ysf71cxTrfgJ8OKVUSmiMUvMOqo8j+tF5kYchVpZ/BPhQXoi78YBhtj6I6JpOzbaZhKIeRXTzppKfurxTNhFjqZGh+xphBhenlLpOha7uRyjm7Gw7jgiNeSRRn15inT5IMzzivcRYsDEebETpXt7rONAYRryb8Boq0qptBv5PSumrvZQ7ktKTfxoWsi8C5xXc5VrgopTSb8uWZZjIujWHEop5HHAGEbuy0ymH24lAztcSCnc3YRXNS91cGtkDp9Fqnk4kFi2yqmce8C3gapq5KroydhSU8ylEerVTC+5yO3BBSmmn0JEDicVSaY3kC+rUuuUeJAzv/RebHzZBYznYK+zHRHEXqP+cI//FRqDifsgy3fYrkFrxDbOw9UOF+iTDZ6woS9W3WXO8ykFDfYb54UYq9eAoA2M1SStuswQDR4Hy9zRydRTJJdJgrQO+GikXI0ljkVAZI7nFMPRMkmE8icfih3XLVwT1nDHkb5VFt+yyL7CYS95IfqmeULVsfcOIdtVJq6h6lSVGxBpmbB98a6DXXY5EvXmU7MussBtqhKa8usP7bp01ZdWqHHVvwxlyS4cn5ffq+XXLXzfZeRjNXPsYIqJX3NkZ9usVlJEM17srOrzPVH+otsvsOz4wIoblxTZtxRz11fZpAD9oGAucR/PxuuXqBPXcUfK/qMRj76O+Rr2ui3vrdisOVzmQqC9U/9TFCbvLsL52khJ56DG8KraNOhfPzN9zcMgUZWkm+wa158l+9cjsfri7i3tpdbbvIC3D6y9G/P43qwu6OIHrjKVDfY+/WQdG4N95I+q/3iHMC6L+OJN/zFicBY/zZCO8SJEpnNFsMabFZpZUreHHZhqrpe3OXBvmGLE/iqzWGVrU74yo81DmvbAZSv99Xew7y5jGmmP3fFNtl5V6YqNOUT9gvhPoWGw0nrQvVw+puz5lYzOmjeo/1y1PNxhe9nMtmM/EiF7wEvUH7hyjpijbjQUBfY/HM7SohxhZbu7q8qRrhOW72Fh1MnTdtlaojx9Rv+fWLU+3mLOyx+gZvdCYH+22d6S6yYidW3Rp2iSjMQbyr1av6eFCqK5Uv28kcZxdd726Rd3fWMWxTZ1RtzxlYkSUu9B4cHbbE2qw2Mg8XWkYyjIofQF3lajPAF4FPJdwNu2W+4nc5JcSOQmuSymt7V3C/qDeBhySUiotq1AdGJmcTgWeBDyFWOTd6/TT9cCXgf/uJtREHQyVEjbInm4vBV5MeBz0yhLgGsL74Arg5pTShhKOWwnq04E9UkqV574oE6MLegJwNuEhchbhNdIr64GfAF8FLikSpmOQGEolbGD4gj0NeAnwLMJxtgwWAjcSLjXXEEpZ2EF0kkA9iFC6M4AzgdOIWDRl8Qfg28D3hvn6DLUSjsTwY3wO4bv2RHpzKB3NJsK/7UYiaNVNhK/ewongkFwEwxI9m4iwdioRLe44wpG5TG4Hfgx8N6VUSwqAshk3SjgSY67wOYRj8dmU760OMa68jwgpOJe4Of5MeH0vTiltqqDMWjHWqB5ChOs4JttOIrzpZ1JeT2Q0dwA/J8JnXt5PB+V+MC6VcCTG0ranEokpzyFipVTJFpqRyxYQIQUXECEalmS/rQQ2DtrNZATg2pc4R4cQsXKmEx7yM4iwFVOoJqzhSB4keh2/AH4KXJ1S2lJxmbUx7pVwJEYy07OIceQ5RGDafjsQP0AYElYTyriGCFa0ggh8uyZ7XUd0gzdn25bslez77bRmFyLYViK65A/LXvfKtv2JYFP7E/FuDs62/Ue81hGMaikxxvsl8JuU0q01yFALE0oJR5PNF54NnAs8juhW9ZbQsVoaircNaGcBbEyED3JdVhKt3RVEGus5VcaTGWQmtBKOJBvvNAIsnQU8JvvccW6BSVpyH2HQ+iNwFXB9SmlFvSINBpNK2AYjOcmJRCzKM7L3s6jG0DOeWE5ETruRiPp2PTC337kkhoVJJewQdRpwNDH/9UiitZxFhPgrc1pkGFhDxAW9E7iVSOByC3B3SmlNnYINE5NKWAI242w2LImzCcWcSVgTpxDd2kEeo7ViG2FAWkZ0J+8lpgvmE4q3MKW0tDbpxgmTSlgxaiKsjo3I24fQDB9/EBHw90BCSffNtj0Iq2bZltsHaFpZ1xMW2PWEZXYZYSxZnG3LstdVE9Vg0i8mlXCAMOKt7pFtexNTCntmn3fPPu9OWEb3IcK2j7SSPgg01rxuJaYythILCzZnnzc2Po/nubdh4v8DdbWivpaBu+gAAAAASUVORK5CYII=")));
    header_logo.leftAlignImage();
    header_logo.imageSize = new Size(30, 30);

    let nickname_label = header.addText(options.nickName);

    nickname_label.minimumScaleFactor = 0.3;
    nickname_label.font = Font.mediumRoundedSystemFont(14);
    nickname_label.textColor = getWidgetTextColor(options);
    nickname_label.centerAlignText();

    header.addSpacer(30);

    stack.addSpacer(3)

    let status_row = stack.addStack();
    status_row.layoutHorizontally();
    status_row.centerAlignContent();
    status_row.size = new Size(0, 0);
    status_row.spacing = 5;

    let status_column_1 = status_row.addStack();
    status_column_1.layoutVertically();
    status_column_1.centerAlignContent();
    status_column_1.size = new Size(25, 0);
    let status_column_2 = status_row.addStack();
    status_column_2.layoutVertically();
    status_column_2.centerAlignContent();
    let status_column_3 = status_row.addStack();
    status_column_3.layoutVertically();
    status_column_3.centerAlignContent();
    status_column_3.size = new Size(25, 0);

    let image = await draw_meter({
        label: `${options.value}%\n${options.remainingDistance}`,
        bg_opacity: 0.5,
        show_car_status: false,
        show_car_icon: false, ...options
    });

    let status_image = status_column_2.addImage(image);
    status_image.centerAlignImage();
    status_image.applyFillingContentMode();
    status_column_2.size = new Size(0, 0);

    let {column_1_options, column_3_options} = Object.keys(options).reduce((acc, key) => {
        if (!["charging", "plugged_in", "blower_on", "remainingChargeTime"].includes(key) && !key.startsWith("window")) {
            acc.column_1_options[key] = options[key];
        } else {
            acc.column_3_options[key] = options[key];
        }
        return acc;
    }, {column_1_options: {}, column_3_options: {}});

    populate_status(status_column_1, column_1_options);
    populate_status(status_column_3, column_3_options);

    let status_text_line = stack.addStack();
    // status_text_line.spacing = 15;
    status_text_line.layoutHorizontally();
    status_text_line.centerAlignContent();

    let status_text_column_1 = status_text_line.addStack()
    status_text_column_1.layoutHorizontally();
    status_text_column_1.centerAlignContent();

    status_text_column_1.size = new Size(80, 0);
    status_text_column_1.addSpacer(4);

    let status_text_1 = status_text_column_1.addText(status_column_1.description || "");
    status_text_1.font = Font.boldRoundedSystemFont(10);
    status_text_1.textColor = getWidgetTextColor(options);

    status_text_column_1.addSpacer();

    let status_text_column_2 = status_text_line.addStack()
    status_text_column_2.layoutHorizontally();
    status_text_column_2.centerAlignContent();
    status_text_column_2.size = new Size(80, 0);

    status_text_column_2.addSpacer();

    let status_2 = status_column_3.description || "";
    let status_text_2;

    // Check if the status is a Date instance
    if (status_2 instanceof Date) {
        let charge_countdown = status_text_column_2.addStack();
        charge_countdown.layoutHorizontally();
        charge_countdown.centerAlignContent();
        charge_countdown.spacing = 1;

        let countdown_symbol = SFSymbol.named("battery.100percent.bolt");
        countdown_symbol.applyFont(Font.lightSystemFont(18));

        let charge_symbol = charge_countdown.addImage(countdown_symbol.image);
        charge_symbol.tintColor = Color.white();
        charge_symbol.imageSize = new Size(20, 14);
        charge_symbol.rightAlignImage();

        status_text_2 = charge_countdown.addDate(status_2);
        status_text_2.applyTimerStyle();

    } else {
        status_text_2 = status_text_column_2.addText(status_2);
    }

    status_text_2.font = Font.boldRoundedSystemFont(10);
    status_text_2.textColor = getWidgetTextColor(options);
    status_text_2.centerAlignText();
    status_text_2.minimumScaleFactor = 0.3;

    status_text_column_2.addSpacer(3);

    stack.addSpacer(3);
    let footer = stack.addStack();
    footer.layoutHorizontally();
    footer.spacing = 3;
    footer.centerAlignContent();
    footer.setPadding(0, 8, 0, 8);

    let updated_symbol = SFSymbol.named("clock.arrow.circlepath");
    updated_symbol.applyFont(Font.lightSystemFont(10));

    let updated_label = footer.addImage(updated_symbol.image);
    updated_label.imageSize = new Size(9, 9);
    updated_label.tintColor = Color.white();
    updated_label.rightAlignImage();

    let footer_text = footer.addDate(options.lastUpdated);
    footer_text.applyRelativeStyle();
    footer_text.font = Font.lightSystemFont(8);
    footer_text.textColor = getWidgetTextColor(options);

    return widget;
}

async function createAccessoryWidget(options) {// Create Widget
    let widget = new ListWidget();

    if (options) {
        let stack = widget.addStack();

        if (options.lockscreen_widget_background) {
            stack.cornerRadius = 10;
            stack.backgroundColor = Color.black();
        }

        if (config.widgetFamily === "accessoryCircular") {
            let image = await draw_meter(options);
            stack.addImage(image);
            stack.setPadding(0, 0, 0, 0);

        } else if (config.widgetFamily === "accessoryInline") {
            options.show_car_icon = false;
            let image = await draw_meter(options);
            stack.addImage(image);
            stack.setPadding(0, 0, 0, 0);
            stack.layoutHorizontally();
            stack.addText(options.nickName);

        } else {
            let row = stack.addStack();

            let image = await draw_meter({show_car_status: false, show_car_icon: false, ...options});
            row.addImage(image);
            row.spacing = 1;

            let column = row.addStack();
            column.layoutVertically();
            column.spacing = 4;
            column.topAlignContent();
            column.size = new Size(0, 60);

            let header = column.addStack();
            header.layoutHorizontally();
            header.centerAlignContent();
            header.spacing = 3;

            let status = column.addStack();
            status.layoutHorizontally();
            status.centerAlignContent();
            status.size = new Size(0, 18);
            status.spacing = 1;

            let update_line = column.addStack();
            update_line.layoutHorizontally();
            update_line.centerAlignContent();
            update_line.spacing = 5

            let updated_symbol = SFSymbol.named("clock.arrow.circlepath");
            updated_symbol.applyFont(Font.lightSystemFont(9));

            let updated_label = update_line.addImage(updated_symbol.image);
            updated_label.imageSize = new Size(9, 9);

            let updated_text = update_line.addDate(options.lastUpdated);
            updated_text.applyRelativeStyle();
            updated_text.font = Font.lightSystemFont(9);
            updated_text.lineLimit = 1;
            updated_text.size = new Size(0, 9);

            let icon = SFSymbol.named("car.fill").image;
            let header_icon = header.addImage(icon);
            header_icon.imageSize = new Size(15, 15);
            header_icon.leftAlignImage();

            let nickname_label = header.addText(options.nickName);
            nickname_label.minimumScaleFactor = 0.5;
            nickname_label.font = Font.mediumRoundedSystemFont(9);
            populate_status(status, options);

            nickname_label.lineLimit = 2;
        }
    }

    return widget
}

async function createLoginWidget(options) {
    const widget = new ListWidget();

    let symbol = SFSymbol.named("person.crop.circle.fill.badge.xmark");
    symbol.applyFont(Font.systemFont(100));

    switch (config.widgetFamily) {
        case "accessoryCircular":
            widget.addImage(symbol.image);
            break;

        default:
            let stack = widget.addStack();
            stack.centerAlignContent();

            if (config.widgetFamily === "small") {
                stack.layoutVertically();
            }

            let user_image;
            if (config.widgetFamily && config.widgetFamily.includes("accessory")) {
                user_image = symbol.image;

            } else {
                setWidgetBackground(widget, options);
                let image_data = Data.fromBase64String("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");
                if (getWidgetTextColor(options).hex === Color.white().hex) {
                    image_data = Data.fromBase64String((await Utilities.executeInWebView({
                        func: Utilities.invertBase64Image,
                        args: [image_data.toBase64String()]
                    })).replace(/^data:image\/[a-z]+;base64,/, ""));
                }

                user_image = Image.fromData(image_data);
            }

            const image = stack.addImage(user_image);
            image.centerAlignImage();

            let prompt = stack.addText("Please login to Solterra Connect.");
            prompt.minimumScaleFactor = 0.2;
            prompt.textColor = getWidgetTextColor(options);
            break;
    }

    return widget;
}

function populate_status(container, options) {
    let icon_count = 0;
    let description;
    const icons = [];

    for (let option in options) {
        if (options[option] === true) {
            switch (option) {
                case "charging":
                    icons.push(SFSymbol.named("bolt.fill"));
                    description = options.remainingChargeTime;
                    break;

                case "plugged_in":
                    if (options.charging === false) {
                        icons.push(SFSymbol.named("powercord.fill"));
                        description = "Plugged In";
                    }
                    break;

                case "blower_on":
                    icons.push(SFSymbol.named("fan.fill"));
                    description = "A/C Running";
                    break;

                case "door_open":
                    const doorPositions = {
                        "front.left": options.door_d_f_open,
                        "rear.left": options.door_d_r_open,
                        "front.right": options.door_p_f_open,
                        "rear.right": options.door_p_r_open
                    };

                    let open_doors = Object.keys(doorPositions).filter(position => doorPositions[position]);

                    icons.push(SFSymbol.named(`car.top.door.${open_doors.join(".and.")}.open.fill`));
                    description = "Door(s) Open";
                    break;

                case "door_unlocked":
                    icons.push(SFSymbol.named("lock.open.fill"));
                    description = "Unlocked";
                    break;

                case "liftgate_open":
                    icons.push(SFSymbol.named("suv.side.rear.open.fill"));
                    description = "Liftgate Open";
                    break;

                case "window_open":
                    icons.push(SFSymbol.named("arrowtriangle.up.arrowtriangle.down.window.left"));
                    description = "Window(s) Open";
                    break;
            }

        } else if (options[option] === false) {
            switch (option) {
                case "door_unlocked":
                    if (!options.charging) {
                        icons.push(SFSymbol.named("lock.fill"));
                        description = "Locked";
                    }
            }
        }
    }

    let icon_size;
    if (config.runsInAccessoryWidget) {
        icon_size = 12 - ((icons.length > 4) ? icons.length - 4 : 0);
    } else {
        icon_size = 15;
    }

    for (const icon of icons) {
        icon.applyFont(Font.systemFont(icon_size));
        let image = container.addImage(icon.image);
        image.centerAlignImage();
        image.tintColor = Color.white();
    }

    if (config.runsInAccessoryWidget && description && icons.length < 3) {
        if (description instanceof Date) {
            description = `${getTimeDifferenceDescription(description)} left`
        }

        let label = container.addText(description);
        label.font = Font.boldRoundedSystemFont(10);
        label.textColor = Color.white();
        label.centerAlignText();
        label.minimumScaleFactor = 0.4;
    } else {
        container.description = description;
        // console.log(description);
    }

    return container;
}

async function draw_meter(options = {}) {

    // JavaScript code to create a canvas, draw something, and then convert it to a base64 image
    // Create a new WebView instance
    let wv = new WebView();

    // HTML content with inline JavaScript using Path2D to draw an arc
    let htmlContent = `
        <html>
        <head>
        </head>
        <body>
        <div id="logs"></div>
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
                        bg_opacity: 1.0,
                        glyph_color: null,
                        label: true,
                        line_spacing: 2,
                        show_car_status: true,
                        show_car_icon: true,
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

              if (options.label && options.show_car_icon) {
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
                ctx.globalAlpha = options.bg_opacity;
                ctx.fill();
                ctx.globalAlpha = 1.0;
                
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
                if (options.show_car_status && options.door_unlocked) {
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
                  let lines;
                  
                  if (typeof options.label === "boolean") {
                    lines = [\`$\{options.value\}%\`];
                  } else {
                    lines = options.label.split('\\n');
                  }

                  ctx.save();
                  let fontSize = 45*scale_factor;
                  document.getElementById('logs').innerText += "\\n" + fontSize;
                  ctx.font = \`bold $\{fontSize\}px -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif\`;
                  
                  //fontSize = fitTextToWidth(ctx, lines[0], 2*(radius - weight)-15);
                  document.getElementById('logs').innerText += "\\n" + fontSize;
                  
                  // Align text for centering
                  ctx.textAlign = 'center'; // Center horizontally
                  ctx.textBaseline = 'middle'; // Center vertically
                  
                  let additionalHeight = 0;
                  let lineHeights = lines.map((line, i) => {
                    let font_size = i === 0 ? fontSize : fontSize * 0.5;
                    if (i > 0) {
                      additionalHeight += font_size*options.line_spacing;
                    }
                    return font_size;
                  });
                  document.getElementById('logs').innerText += "\\n" + JSON.stringify(lineHeights);
                  
                  let currentY = label_origin.y - additionalHeight/4;

                  // Adjust font size
                  lines.forEach((line, i) => {
                    ctx.font = \`bold $\{lineHeights[i]\}px -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif\`;
                    ctx.fillText(line, label_origin.x, currentY);
                    currentY += lineHeights[i+1]*options.line_spacing;
                  });
                  
                  ctx.restore();
                }

                let charge = new Path2D(
                    "M 33.900002 22.563499 C 33.732738 22.218746 33.383186 21.999886 33 22 L 22.580002 22 L 29.903801 1.4277 C 30.05072 1.11795 30.028622 0.754509 29.845249 0.464844 C 29.661877 0.175175 29.342831 -0.000282 29 0 C 29 0 0.0874 32.590797 0.0874 32.590797 C -0.051372 32.900238 -0.023859 33.258919 0.160482 33.543571 C 0.344824 33.828224 0.660871 34.000053 1 34 L 10.759199 34 L 6.0229 55.787102 C 5.923433 56.242355 6.1516 56.705971 6.573009 56.904877 C 6.994419 57.103783 7.49736 56.985252 7.785601 56.619099 L 33.785599 23.619102 C 34.022514 23.318085 34.066925 22.908279 33.900002 22.563499 Z"
                  );
                let car_body = new Path2D(
                    "M 633.1875 204.421875 L 633.1875 204.53125 L 633.21875 204.640625 L 633.265625 204.78125 L 633.375 205.015625 L 633.578125 205.3125 L 633.96875 205.765625 L 634.921875 206.65625 L 636.359375 207.859375 L 637.484375 208.859375 L 638.21875 209.6875 L 638.71875 210.46875 L 639 211.125 L 639.171875 211.796875 L 639.25 212.609375 L 639.140625 213.40625 L 638.890625 214.1875 L 638.5 214.859375 L 638.0625 215.453125 L 637.75 215.78125 L 636.875 216.640625 L 635.015625 218.3125 L 633.03125 219.921875 L 630.953125 221.453125 L 628.78125 222.90625 L 626.53125 224.3125 L 624.234375 225.609375 L 621.875 226.875 L 619.46875 228.0625 L 617.046875 229.203125 L 614.578125 230.265625 L 612.125 231.28125 L 609.65625 232.234375 L 607.234375 233.125 L 604.796875 233.96875 L 602.421875 234.734375 L 598.9375 235.828125 L 594.53125 237.078125 L 590.484375 238.125 L 586.859375 239 L 582.390625 239.96875 L 578.90625 240.625 L 578.359375 240.703125 L 572.25 240.703125 L 573.578125 236.453125 L 574.09375 234.625 L 574.578125 232.59375 L 574.96875 230.609375 L 575.265625 228.671875 L 575.515625 226.59375 L 575.671875 224.65625 L 575.75 222.484375 L 575.765625 221.46875 L 575.75 220.109375 L 575.609375 217.40625 L 575.34375 214.765625 L 574.9375 212.1875 L 574.40625 209.625 L 573.765625 207.125 L 573 204.65625 L 572.125 202.265625 L 571.125 199.9375 L 570.015625 197.65625 L 568.796875 195.421875 L 567.546875 193.328125 L 566.09375 191.1875 L 564.640625 189.265625 L 562.96875 187.234375 L 561.296875 185.390625 L 559.515625 183.609375 L 557.75 182.015625 L 555.71875 180.34375 L 553.703125 178.828125 L 551.71875 177.484375 L 549.5 176.140625 L 547.234375 174.921875 L 544.9375 173.8125 L 542.59375 172.8125 L 540.328125 171.984375 L 537.8125 171.203125 L 535.359375 170.578125 L 532.6875 170.03125 L 530.109375 169.625 L 527.578125 169.375 L 524.78125 169.234375 L 523.484375 169.21875 L 522.203125 169.234375 L 519.40625 169.375 L 516.875 169.625 L 514.296875 170.03125 L 511.625 170.578125 L 509.171875 171.203125 L 506.65625 171.984375 L 504.390625 172.8125 L 502.046875 173.8125 L 499.65625 174.96875 L 497.421875 176.171875 L 495.265625 177.484375 L 493.28125 178.828125 L 491.265625 180.34375 L 489.234375 182.015625 L 487.390625 183.6875 L 485.609375 185.46875 L 484.015625 187.234375 L 482.34375 189.265625 L 480.828125 191.28125 L 479.484375 193.265625 L 478.109375 195.53125 L 476.90625 197.75 L 475.8125 200.03125 L 474.8125 202.390625 L 473.984375 204.65625 L 473.1875 207.234375 L 472.546875 209.75 L 472.03125 212.296875 L 471.625 214.90625 L 471.375 217.40625 L 471.234375 220.203125 L 471.21875 221.53125 L 471.234375 222.484375 L 471.3125 224.625 L 471.46875 226.5625 L 471.703125 228.640625 L 472 230.546875 L 472.390625 232.515625 L 472.828125 234.421875 L 473.375 236.375 L 474.640625 240.578125 L 404.015625 240.46875 L 290.46875 240.203125 L 217.265625 239.96875 L 180.578125 239.8125 L 181.796875 235.734375 L 182.296875 233.828125 L 182.703125 232 L 183.0625 230.109375 L 183.34375 228.21875 L 183.53125 226.421875 L 183.671875 224.390625 L 183.75 222.421875 L 183.765625 221.46875 L 183.75 220.109375 L 183.609375 217.40625 L 183.34375 214.765625 L 182.9375 212.1875 L 182.40625 209.625 L 181.765625 207.125 L 181 204.65625 L 180.125 202.265625 L 179.125 199.9375 L 178.015625 197.65625 L 176.796875 195.421875 L 175.546875 193.328125 L 174.09375 191.1875 L 172.640625 189.265625 L 170.96875 187.234375 L 169.296875 185.390625 L 167.515625 183.609375 L 165.75 182.015625 L 163.71875 180.34375 L 161.703125 178.828125 L 159.71875 177.484375 L 157.5 176.140625 L 155.234375 174.921875 L 152.9375 173.8125 L 150.59375 172.8125 L 148.328125 171.984375 L 145.8125 171.203125 L 143.359375 170.578125 L 140.6875 170.03125 L 138.109375 169.625 L 135.578125 169.375 L 132.78125 169.234375 L 131.484375 169.21875 L 130.203125 169.234375 L 127.40625 169.375 L 124.875 169.625 L 122.296875 170.03125 L 119.625 170.578125 L 117.171875 171.203125 L 114.65625 171.984375 L 112.390625 172.8125 L 110.046875 173.8125 L 107.65625 174.96875 L 105.421875 176.171875 L 103.265625 177.484375 L 101.28125 178.828125 L 99.265625 180.34375 L 97.234375 182.015625 L 95.390625 183.6875 L 93.609375 185.46875 L 92.015625 187.234375 L 90.34375 189.265625 L 88.828125 191.28125 L 87.484375 193.265625 L 86.109375 195.53125 L 84.90625 197.75 L 83.8125 200.03125 L 82.8125 202.390625 L 81.984375 204.65625 L 81.1875 207.234375 L 80.546875 209.75 L 80.03125 212.296875 L 79.625 214.90625 L 79.375 217.40625 L 79.234375 220.203125 L 79.21875 221.53125 L 79.234375 222.375 L 79.296875 224.21875 L 79.421875 226.125 L 79.59375 227.8125 L 79.84375 229.609375 L 79.859375 229.609375 L 80.171875 231.453125 L 80.15625 231.453125 L 80.515625 233.109375 L 80.9375 234.828125 L 82.109375 238.96875 L 74.84375 238.796875 L 71.171875 238.65625 L 70.015625 238.5625 L 69.5 238.453125 L 68.671875 238.25 L 67.578125 237.109375 L 66.3125 235.875 L 65.21875 234.84375 L 64.046875 233.828125 L 62.984375 232.9375 L 62 232.1875 L 61.09375 231.546875 L 60.21875 230.96875 L 58.796875 230.125 L 57.15625 229.265625 L 55.65625 228.59375 L 54.25 228.046875 L 54.25 228.0625 L 52.765625 227.515625 L 51.296875 226.9375 L 49.765625 226.296875 L 48.625 225.6875 L 47.828125 225.25 L 47.03125 224.71875 L 46.234375 224.140625 L 45.4375 223.484375 L 44.640625 222.765625 L 43.828125 221.953125 L 43.015625 221.0625 L 42.203125 220.09375 L 41.40625 219.046875 L 40.953125 218.46875 L 40.546875 217.859375 L 39.859375 216.71875 L 39.1875 215.453125 L 38.59375 214.109375 L 38.03125 212.703125 L 37.515625 211.203125 L 37.0625 209.640625 L 36.640625 208.03125 L 36.25 206.328125 L 35.921875 204.5625 L 35.625 202.75 L 35.359375 200.875 L 35.140625 198.921875 L 34.96875 196.953125 L 34.734375 193.890625 L 34.5625 189.65625 L 34.53125 185.265625 L 34.640625 180.71875 L 34.859375 176.125 L 35.203125 171.421875 L 35.65625 166.671875 L 36.234375 161.90625 L 36.921875 157.15625 L 37.71875 152.4375 L 38.609375 147.78125 L 39.59375 143.203125 L 40.6875 138.75 L 41.875 134.4375 L 43.15625 130.3125 L 44.171875 127.328125 L 44.875 125.40625 L 45.59375 123.546875 L 46.34375 121.734375 L 47.125 119.984375 L 47.90625 118.3125 L 48.71875 116.6875 L 49.5625 115.171875 L 50.40625 113.71875 L 51.296875 112.328125 L 52.21875 111.015625 L 53.140625 109.8125 L 54.109375 108.671875 L 55.109375 107.625 L 56.15625 106.671875 L 57.21875 105.828125 L 58.34375 105.078125 L 59.515625 104.46875 L 60.71875 103.96875 L 61.96875 103.625 L 62.59375 103.53125 L 63.375 103.40625 L 64.8125 103.15625 L 64.8125 103.140625 L 66.390625 102.8125 L 66.390625 102.828125 L 67.859375 102.484375 L 70.265625 101.84375 L 73.4375 100.890625 L 76.65625 99.78125 L 79.84375 98.5625 L 79.84375 98.546875 L 83.21875 97.140625 L 86.5625 95.625 L 89.953125 94 L 93.296875 92.28125 L 96.765625 90.421875 L 100.21875 88.5 L 103.65625 86.5 L 107.125 84.4375 L 110.578125 82.296875 L 114.03125 80.125 L 119.1875 76.796875 L 125.984375 72.265625 L 136 65.4375 L 145.5625 58.859375 L 151.6875 54.71875 L 157.53125 50.859375 L 161.71875 48.203125 L 164.40625 46.578125 L 165.71875 45.796875 L 166.546875 45.3125 L 168.25 44.40625 L 170.046875 43.53125 L 171.90625 42.703125 L 173.84375 41.890625 L 175.859375 41.140625 L 177.9375 40.390625 L 180.078125 39.703125 L 182.296875 39.03125 L 184.578125 38.390625 L 186.921875 37.796875 L 189.3125 37.21875 L 193.015625 36.390625 L 198.15625 35.40625 L 203.484375 34.515625 L 208.96875 33.734375 L 214.640625 33.046875 L 220.453125 32.4375 L 226.359375 31.921875 L 232.390625 31.46875 L 238.515625 31.109375 L 244.6875 30.828125 L 250.90625 30.609375 L 257.15625 30.4375 L 263.390625 30.34375 L 269.625 30.296875 L 275.84375 30.296875 L 281.984375 30.34375 L 291.078125 30.5 L 302.8125 30.8125 L 313.984375 31.25 L 324.4375 31.75 L 334.015625 32.28125 L 338.359375 32.5625 L 340.546875 32.71875 L 344.84375 33.140625 L 349.125 33.703125 L 353.375 34.40625 L 357.609375 35.21875 L 361.8125 36.203125 L 365.984375 37.265625 L 370.15625 38.46875 L 374.3125 39.765625 L 378.4375 41.171875 L 382.578125 42.6875 L 386.6875 44.3125 L 390.796875 46.015625 L 394.921875 47.796875 L 399.046875 49.671875 L 403.140625 51.625 L 407.265625 53.640625 L 411.40625 55.734375 L 415.546875 57.875 L 419.71875 60.09375 L 426 63.515625 L 434.453125 68.234375 L 447.3125 75.5625 L 460.5625 83.140625 L 469.59375 88.25 L 474.203125 90.8125 L 474.671875 91.0625 L 475.6875 91.59375 L 477.359375 92.375 L 479.5625 93.25 L 481.90625 94.0625 L 484.484375 94.8125 L 487.046875 95.46875 L 489.640625 96.03125 L 492.421875 96.546875 L 495.328125 97.015625 L 498.21875 97.4375 L 498.21875 97.421875 L 502.828125 97.984375 L 512.40625 98.96875 L 522.5625 99.984375 L 527.8125 100.578125 L 531.359375 101.046875 L 534.921875 101.5625 L 538.53125 102.140625 L 542.171875 102.8125 L 545.828125 103.5625 L 549.5 104.40625 L 553.1875 105.359375 L 556.890625 106.421875 L 560.59375 107.609375 L 564.296875 108.9375 L 567.96875 110.40625 L 570.75 111.609375 L 572.59375 112.46875 L 574.421875 113.359375 L 576.265625 114.3125 L 577.171875 114.796875 L 579.125 115.84375 L 582.921875 117.984375 L 586.65625 120.1875 L 590.296875 122.4375 L 593.828125 124.75 L 597.265625 127.09375 L 600.59375 129.5 L 603.828125 131.953125 L 606.921875 134.453125 L 609.921875 137 L 612.765625 139.578125 L 615.5 142.21875 L 618.09375 144.890625 L 620.546875 147.59375 L 622.859375 150.359375 L 625.015625 153.15625 L 626.515625 155.265625 L 627.484375 156.71875 L 628.390625 158.15625 L 629.265625 159.578125 L 630.109375 161.046875 L 630.890625 162.515625 L 631.640625 164 L 632.34375 165.484375 L 632.984375 166.96875 L 633.59375 168.484375 L 634.15625 169.984375 L 634.671875 171.5 L 635.140625 173.03125 L 635.546875 174.578125 L 635.90625 176.125 L 636.21875 177.671875 L 636.484375 179.234375 L 636.6875 180.796875 L 636.84375 182.359375 L 636.953125 183.9375 L 636.984375 185.53125 L 636.96875 187.109375 L 636.90625 188.6875 L 636.78125 190.296875 L 636.59375 191.890625 L 636.359375 193.5 L 636.046875 195.109375 L 635.6875 196.6875 L 635.265625 198.3125 L 634.765625 199.9375 L 634.234375 201.53125 L 633.625 203.125 L 633.3125 203.921875 L 633.234375 204.15625 Z"
                  );
            
                if (options.show_car_status) {
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
                }

                // Draw behind-body car status indicators
                
                let bolt_pos = {x: car_pos.x+68.5, y: car_pos.y+30.5};
                let bolt_scale = {x: car_scale.x*1.5, y: car_scale.x*1.5};

                if (options.show_car_icon && options.show_car_status) {
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

                if (options.show_car_icon) {
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
              
              document.getElementById('logs').innerText += "\\n" + newSize;

              // Return the adjusted size
              return newSize;
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

    const logs = await wv.evaluateJavaScript("document.getElementById('logs').innerText");
    DebugLogger.log(logs, true);

    // Now 'base64Image' contains a base64-encoded PNG of the canvas
    return Image.fromData(image_data);
}

function getTimeDifferenceDescription(date, compare_to = new Date()) {
    let diffInMilliseconds = compare_to - date;

    let suffix = ' ago';
    if (diffInMilliseconds < 0) {
        suffix = '';
    }

    diffInMilliseconds = Math.abs(diffInMilliseconds); // Make sure the difference is positive

    let seconds = diffInMilliseconds / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    let weeks = days / 7;
    let months = days / 30;

    if (months >= 1) {
        return `${Math.floor(months)} month${Math.floor(months) > 1 ? 's' : ''}${suffix}`;
    } else if (weeks >= 1) {
        return `${Math.floor(weeks)} week${Math.floor(weeks) > 1 ? 's' : ''}${suffix}`;
    } else if (days >= 1) {
        if (Math.floor(days) > 1 && days % 1 >= 0.5) {
            return `${Math.floor(days)} days and ${Math.round((days % 1) * 24)} hours${suffix}`;
        } else {
            return `${Math.floor(days)} day${Math.floor(days) > 1 ? 's' : ''}${suffix}`;
        }
    } else if (hours >= 1) {
        if (Math.floor(hours) > 1 && hours % 1 >= 0.5) {
            return `${Math.floor(hours)} hours and ${Math.round((hours % 1) * 60)} minutes${suffix}`;
        } else {
            return `${Math.floor(hours)} hour${Math.floor(hours) > 1 ? 's' : ''}${suffix}`;
        }
    } else if (minutes >= 1) {
        return `${Math.floor(minutes)} minute${Math.floor(minutes) > 1 ? 's' : ''}${suffix}`;
    } else {
        return `${Math.floor(seconds)} second${Math.floor(seconds) !== 1 ? 's' : ''}${suffix}`;
    }
}

// return a new promise, and a function that resolves or rejects the promise based on the boolean value the function is called with
function callback_promise() {
    let resolve, reject;
    let promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });

    const callback = (bool) => bool ? resolve() : reject();

    return {
        promise: promise,
        callback: callback
    };
}

async function shortcutOutput(app, query) {
    if (!app.is_logged_in || !app._prefs.vehicle) {
        let message;
        if (!app.is_logged_in) {
            message = "You don't seem to be logged in.  Please run the app and log in.";
        } else {
            message = "You don't seem to have a vehicle selected.  Please run the app and select a vehicle.";
        }
        await Speech.speak(message);

        const header_image = Image.fromData(Data.fromBase64String('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'));

        const table = new UITable();
        table.showSeparators = true;
        const header_row = new UITableRow();
        header_row.isHeader = true;
        header_row.height = 100;
        header_row.backgroundColor = Color.white();
        const header_cell = header_row.addImage(header_image);
        header_cell.centerAligned();
        table.addRow(header_row);
        const row = new UITableRow();
        row.backgroundColor = Color.clear();
        const promt_cell = row.addText("Tap to open the app.");
        promt_cell.centerAligned();
        table.addRow(row);

        await table.present();

        return null;
    }

    let result = {
        value: null,
        followup: null,
        prompt: null,
        required_action: null,
        steps: []
    };

    switch (query) {

        case "is-locked":
            result = await app.vehicle.is_locked();
            result = result !== null && result !== undefined;
            break;

        case "remote-door-lock":
            result = await app.vehicle.remote_door_lock();
            result = result !== null && result !== undefined;
            break;

        case "remote-door-unlock":
            result = await app.vehicle.remote_door_unlock();
            result = result !== null && result !== undefined;
            break;

        case "remote-trunk-lock":
            result = await app.vehicle.remote_trunk_lock();
            result = result !== null && result !== undefined;
            break;

        case "remote-trunk-unlock":
            result = await app.vehicle.remote_trunk_unlock();
            result = result !== null && result !== undefined;
            break;

        case "remote-engine-start":
            result = await app.vehicle.remote_engine_start();
            result = result !== null && result !== undefined;
            break;

        case "remote-engine-stop":
            result = await app.vehicle.remote_engine_stop();
            result = result !== null && result !== undefined;
            break;

        case "battery-percentage":
            result = await app.vehicle.get_battery_percentage();
            break;

        case "charge-info":
            result = await app.vehicle.get_charge_info();
            break;

        case "car-image":
            result = await app.vehicle.get_car_image();
            break;

    }

    return result;

}

async function main(options = {}) {
    let tba = new ToybaruApp({tokenId: options.tokenId})
    await tba.init();
    let status = {}
    let widget;

    const customizations = tba.fetch_customizations().values;
    let widget_options = {...customizations}
    widget_options.backgroundColor = Color.dynamic(new Color(customizations.widget_color, 1), new Color(customizations.nightshift_widget_color, 1));
    widget_options.backgroundColorGradient = Color.dynamic(new Color(Utilities.darkenHexColor(customizations.widget_color, 0.4), 1), new Color(Utilities.darkenHexColor(customizations.nightshift_widget_color, 0.4), 1));


    tba.save_prefs();

    if (config.runsInWidget) {
        if (tba.is_logged_in) {
            if (tba._prefs.vehicle) {
                status = await tba.vehicle.get_status();
                widget_options = {...widget_options, ...status.get_status_values()};

                switch (config.widgetFamily) {
                    case 'small':
                        widget = await createSmallWidget(widget_options);
                        break;
                    case 'medium':
                        widget = await createMediumWidget(widget_options);
                        break;
                    case 'large':
                        widget = await createLargeWidget(widget_options);
                        break;
                    case 'extraLarge':
                        break;
                    case 'accessoryRectangular':
                    case 'accessoryInline':
                    case 'accessoryCircular':
                        widget = await createAccessoryWidget(widget_options);
                        break;
                    default:
                        widget = await createSmallWidget(widget_options);
                        break;
                }

                widget.refreshAfterDate = new Date(tba.vehicle.next_refresh);

                Script.setWidget(widget);


            }
        } else {
            widget = await createLoginWidget(widget_options);
        }
        Script.setWidget(widget);

    }

    if (config.runsInApp) {
        await tba.launch_app();

    } else if (args.shortcutParameter && typeof args.shortcutParameter === "string") {

        let query = args.shortcutParameter;
        let result = await shortcutOutput(tba, query)

        Script.setShortcutOutput(result);
        Script.complete();
    }


    Script.complete();
}

await main(args.queryParameters);
