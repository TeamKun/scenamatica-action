import * as core from "@actions/core"

export function fail(message: string | Error): void {
    core.setFailed(message)
}

export function warn(message: string): void {
    core.warning(message)
}

export function info(message: string): void {
    core.info(message)
}

export function debug(message: string): void {
    core.debug(message)
}

export interface Args {
    mcVersion: string
    scenamaticaVersion: string
    serverDir: string
    pluginFile: string
    javaVersion: string
}

export function getArguments(): Args {
    return {
        mcVersion: core.getInput("minecraft") ?? "1.16.5",
        scenamaticaVersion: core.getInput("scenamatica", { required: true }),
        serverDir: core.getInput("server-dir") ?? "server",
        pluginFile: core.getInput("plugin", { required: true }),
        javaVersion: core.getInput("java") ?? "17",
    }
}
