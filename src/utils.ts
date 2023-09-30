import * as core from "@actions/core"
import type {PacketTestEnd} from "./packets";
import {TestResultCause} from "./packets";

const DEFAULT_SCENAMATICA_VERSION = "0.8.0"
const ENV_NO_SCENAMATICA = "NO_SCENAMATICA"

const extractTestResults = (results: PacketTestEnd[]) => {
    const total = results.length
    const passed = results.filter((t) => t.cause === TestResultCause.PASSED).length
    const skipped = results.filter((t) => t.cause === TestResultCause.SKIPPED).length
    const cancelled = results.filter((t) => t.cause === TestResultCause.CANCELLED).length

    const failures = results.filter(
        (t) =>
            !(
                t.cause === TestResultCause.PASSED ||
                t.cause === TestResultCause.SKIPPED ||
                t.cause === TestResultCause.CANCELLED
            ),
    ).length


    return {
        total,
        passed,
        failures,
        skipped,
        cancelled,
    }
}

export const isTestSucceed = (results: PacketTestEnd[]) => {
    const {failures} = extractTestResults(results)
    const threshold = getArguments().failThreshold

    return failures <= threshold
}

interface Args {
    mcVersion: string
    scenamaticaVersion: string
    serverDir: string
    pluginFile: string
    javaVersion: string
    githubToken: string
    graphicalSummary: boolean
    failThreshold: number
}

const getArguments = (): Args => {
    return {
        mcVersion: core.getInput("minecraft") || "1.16.5",
        scenamaticaVersion: core.getInput("scenamatica", ) || DEFAULT_SCENAMATICA_VERSION,
        serverDir: core.getInput("server-dir") || "server",
        pluginFile: core.getInput("plugin", { required: true }),
        javaVersion: core.getInput("java") || "17",
        githubToken: core.getInput("github-token") || process.env.GITHUB_TOKEN!,
        graphicalSummary: core.getBooleanInput("graphical-summary"),
        failThreshold: Number.parseInt(core.getInput("fail-threshold"), 10) || 0,
    }
}

const isNoScenamatica = (): boolean => {
    return process.env[ENV_NO_SCENAMATICA] === "true"
}

export { extractTestResults, getArguments, Args, isNoScenamatica }
