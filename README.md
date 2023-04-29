# Scenamatica Scenario Test

Scenamatica is a tool for automatically scenario testing your PaperMC plugins.

## Usage

See [action.yaml](./action.yaml)

```yaml
- uses: TeamKUN/
  with:
    # The path to the plugin jar file.
    plugin: 'target/YourPlugin-1.0.0.jar'
    # The scenamatica version to use.
    scenamatica: '0.4.0'
    # The Minecraft version(default: 1.16.5)
    minecraft: '1.16.5'
    # The server directory to run the tests.
    server-dir: 'server'
```
