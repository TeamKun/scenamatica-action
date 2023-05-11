# [Scenamatica](https://github.com/TeamKun/Scenamatica) Action

[Scenamatica](https://github.com/TeamKun/Scenamatica) is a tool for automatically scenario testing your PaperMC plugins.  
Scenamatica Action is a GitHub Action for running Scenamatica automatically.

## Usage

See [action.yaml](./action.yaml)

```yaml

on:
  push:
  pull_request:

permissions:
  pull-requests: write  # For writing pull request comments(optional)

# ...
steps:
- uses: TeamKUN/
  with:
    # The path to the plugin jar file.
    plugin: "target/YourPlugin-1.0.0.jar"
    # The scenamatica version to use. (default: <DEPENDS ON THE ACTION VERSION>)
    scenamatica: "0.4.0"
    # The Minecraft version(default: 1.16.5)
    minecraft: "1.16.5"
    # The server directory to run the tests. (default: "server")
    server-dir: "server"
    # The token to use for the GitHub API(Writing pull request comments). (default: ${{ github.token }})
    github-token: ${{ github.token }}
```

If you want to run tests on pull requests, you need to set the `pull-requests` permission to `write` in the `permissions` section.

## More Information

Please see the [Scenamatica documentation](https://scenamatica.kunlab.org/) for more information\(ONLY IN JAPANESE).
