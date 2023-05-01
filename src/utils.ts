import * as core from "@actions/core"

const DEFAULT_SCENAMATICA_VERSION = "0.5.6"

const fail = (message: Error | string) => {
    core.setFailed(message)
}

const warn = (message: string) => {
    core.warning(message)
}

const info = (message: string) => {
    core.info(message)
}

const debug = (message: string) => {
    core.debug(message)
}

interface Args {
    mcVersion: string
    scenamaticaVersion: string
    serverDir: string
    pluginFile: string
    javaVersion: string
}

const getArguments = (): Args => {
    return {
        mcVersion: core.getInput("minecraft") || "1.16.5",
        scenamaticaVersion: core.getInput("scenamatica", ) || DEFAULT_SCENAMATICA_VERSION,
        serverDir: core.getInput("server-dir") || "server",
        pluginFile: core.getInput("plugin", { required: true }),
        javaVersion: core.getInput("java") || "17",
    }
}

export { fail, warn, info, debug, getArguments, Args }
