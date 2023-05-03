# [Scenamatica](https://github.com/TeamKun/Scenamatica) Action

[Scenamatica](https://github.com/TeamKun/Scenamatica) is a tool for automatically scenario testing your PaperMC plugins.  
Scenamatica Action is a GitHub Action for running Scenamatica automatically.

## Usage

See [action.yaml](./action.yaml)

```yaml
- uses: TeamKUN/
  with:
    # The path to the plugin jar file.
    plugin: "target/YourPlugin-1.0.0.jar"
    # The scenamatica version to use.
    scenamatica: "0.4.0"
    # The Minecraft version(default: 1.16.5)
    minecraft: "1.16.5"
    # The server directory to run the tests.
    server-dir: "server"
```

## More Information

Please see the [Scenamatica documentation](https://scenamatica.kunlab.org/) for more information\(ONLY IN JAPANESE).
