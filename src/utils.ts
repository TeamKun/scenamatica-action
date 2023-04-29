import * as core from "@actions/core";

export function fail(message: string | Error): void {
    core.setFailed(message);
}

export function warn(message: string): void {
    core.warning(message);
}

export function info(message: string): void {
    core.info(message);
}

export function debug(message: string): void {
    core.debug(message);
}

type Input = {
    mcVersion: string;
    scenamaticaVersion: string;
    serverDir: string;
    pluginFile: string;
}

export function getArguments(): Input {
    return {
        mcVersion: core.getInput("minecraft", {required: true}),
        scenamaticaVersion: core.getInput("scenamatica", {required: true}),
        serverDir: core.getInput("server-dir"),
        pluginFile: core.getInput("plugin", {required: true})
    };
}
