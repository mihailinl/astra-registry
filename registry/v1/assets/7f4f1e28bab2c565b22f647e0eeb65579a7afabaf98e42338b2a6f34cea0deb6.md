# VRM Manager

VRM Manager is an Astra plugin for managing local VRM models, VRoid Hub models, accessories and basic VRM editing.

**Author:** denchik  
**License:** MIT  
**Version:** 1.1.7

![VRM Manager](https://raw.githubusercontent.com/denchik2444/vrm-manager/cf347a05cfa3363253d08b8f2be5819b64fd0536/icon.png)

## Features

- Local VRM library
- VRoid Hub search and downloads
- OAuth 2.0 + PKCE for VRoid Hub
- VRM/GLB inspection
- Object and mesh tree
- Hide/show model nodes
- Save edited `.edited.vrm` copies
- Accessory management
- Direct import into Astra Character Library
- Astra UI page with transparent background and theme integration

## Astra import

`Import to Astra` does not automate clicks in the Astra window.

It detects the Astra Character Library on the local Windows installation and registers the model by creating or updating:

- `pack/models/model.vrm`
- `pack/characters/character/character.toml`
- `library.json`

Before changing `library.json`, the plugin creates a timestamped backup.

The plugin first checks standard Astra AppData locations and can also use the `ASTRA_COMPANION_DIR` environment variable for a custom Character Library location.

## Requirements

- Astra with plugin support
- Windows x64
- Node.js runtime supplied by Astra
- VRoid Hub Client ID and Client Secret for VRoid Hub features

## Permissions

The plugin requests:

- `set_variable`: stores the currently selected VRM path for the Astra session.
- `send_chat_message`: lets the "Use in Astra" action ask Astra to use the selected VRM.

## Development

```text
npm install
npm run build
npm run check

astra-plugin check . --strict
astra-plugin test .
