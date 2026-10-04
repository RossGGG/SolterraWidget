# Solterra Connect Scriptable Script
The main use for this script is to provide iOS Widgets and Siri Shortcut capabilities to a Subaru Solterra vehicle with an active Remote Connect subscription.

### Setup
After you have installed the [Scriptable app](https://scriptable.app), you can use this link to install the Solterra Connect script from this repo.

[![Download with ScriptDude](https://scriptdu.de/download.svg)](https://scriptdu.de?name=Solterra%20Connect&source=https%3A%2F%2Fraw.githubusercontent.com%2FRossGGG%2FSolterraWidget%2Fmain%2FSolterra%2520Connect.js&docs=https%3A%2F%2Fgithub.com%2FRossGGG%2FSolterraWidget%2Fblob%2Fmain%2FREADME.md)

## Widgets
Currently, only the lockscreen (accessory) widgets and the small widget are available.  The widget appearance(s) can be customized in the web app.

| Widget Size | Preview |
| :---: | :---: |
| __accessoryCircular__ | <img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/78f640f0-5dae-46cb-b01b-5b1f5fea69fa" alt="Circular Accessory Widget" height=60 /> |
| __accessoryRectangular__ | <img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/4decd956-c442-4738-832f-528b4bb290f5" alt="Rectangular Accessory Widget" height=60 /> |
| __accessoryInline__ | <img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/0beda685-10da-4041-88bf-520301fd8634" alt="Inline Accessory Widget" height=30 /> |
| __small__ | <img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/a7a8ab2e-30c6-483a-83d5-1b4901b20e78" alt="Small Widget" height=120 /> |

## Siri Shortcuts
Commands and queries can be sent and retrieved from Siri via the available shortcuts.
The included shortcuts can be used a a template for building your own shotcuts, as each starts by asking the script to send a command, or provide a value back to the shortcut.

<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/86288875-21c0-411e-aae0-43dd0d26e5fd" alt="Siri Shortcut Customization" height=300 />
<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/551b2eb6-fc11-49e1-9a65-00c5e463e1b2" alt="Siri Shortcut Example" height=150 />
<br><br>

| Shortcut | Description |
| :----: | :----: |
| Lock My Car | Sends command to lock all vehicle doors |
| Unlock My Car | Sends command to unlock all vehicle doors |
| Is My Car Locked? | Checks the vehicle status and replies if __all__ doors are locked |
| Lock The Car Hatch | Sends command to lock the vehicle liftgate |
| Unlock The Car Hatch | Sends command to unlock the vehicle liftgate |
| Start My Car | Sends command to start the vehicle (runs the climate controls for 20 minutes) |
| Stop My Car | Sends command to turn off the vehicle / climate controls (if it was started remotely) |
| Check My Car Battery | Checks the vehicle status and replies with the state-of-charge and range estimations |
| Check My Car Charge | Checks the vehicle status and replies with the estimated remaining charge time |

## Web App
The script includes a web app, which provides a way for the user to login to their Solterra Connect account and select a vehicle to associate with the script.
The app provides a basic interface to view the car statu and send commands to the car.
Users can also use the app to customize the widget appearance and behavior, and to install the supported Siri Shortcuts to their device.

<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/469867bc-966e-4ecd-8d49-fcba5bf90bff" alt="Web App Login" height=300 />
<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/c37366d2-193c-4cea-8138-46d08f0a76b4" alt="Web App - Vehicle Status" height=300 />
<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/669186b8-9981-419e-b999-8356259e7809" alt="Web App - Widget Customization" height=300 />
<img src="https://github.com/RossGGG/SolterraWidget/assets/5018716/88c8f64e-fb25-4b41-a6a0-dde08acb4ce7" alt="Web App - Siri Shortcuts" height=300 />

### Notes
* Third-party login providers are not currently supported.  This should be able to be added in the future.

### Current North American API authentication

The authentication and gateway configuration were compared with
[bhaggs/ha-toyota-na](https://github.com/bhaggs/ha-toyota-na/tree/fbcc490298578b587b157468414b4de9a9824a03/custom_components/toyota_na/oneapi)
(SubaruConnect integration, snapshot `fbcc490`, October 3, 2026).

| Area | SolterraWidget update |
| --- | --- |
| Login tenant / OAuth client | Retain Subaru driver login, `oneappsdkclient`, and the shared Toyota callback URI |
| Login tree | Use the default authenticate tree, matching the integration |
| Callbacks | Select local login and handle OTP verification/resend confirmations |
| Cookies | Route Scriptable WebView login requests through native networking; retain cookies through discovery, OTP, authorization and token requests |
| Gateway | Switch to `https://onecdn.telematicsct.com/oneapi` and the current resolver key / Subaru headers |
| Refresh | Include callback URI and verifier; preserve tokens on temporary server failures |

Update the Scriptable script and sign in again if your existing session is rejected.
The editable HTML is also embedded in `Solterra Connect.js`; both copies must stay
in sync. Offline regression checks run with `node --test tests/auth.test.cjs`
from the repository directory.

This update has offline coverage, but still needs a real sign-in in Scriptable
on iOS. WebView login requests use a native bridge restricted to discovery and
authentication endpoints on the configured Subaru login realm. This avoids
WebView cross-origin cookie restrictions and keeps server affinity cookies in
the native session used for the subsequent token exchange. The bridge still
needs live verification. Vehicle discovery and remote commands also need live
validation; this change does not port the integration's GraphQL features or
empty-vehicle-list account bootstrap.

The WebView waits for Scriptable's saved-session handoff before starting login,
and suppresses failures from superseded login attempts. Opening Home requests
fresh charging data once while showing the last available reading and a pending
indicator. “Refresh charging” repeats that request. The current realtime endpoint
uses an empty JSON body, device/VIN headers, and the returned `appRequestNo` for
status polling. Polling stops after 12 attempts, five seconds apart; only a newer
vehicle acquisition timestamp counts as updated. On timeout or failure the last
reading remains visible. This updates charging data, not all door/climate data.
