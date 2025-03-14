import * as core from "@actions/core"
import type {PacketTestEnd} from "./packets";
import {TestResultCause} from "./packets";
import {ENV_NO_SCENAMATICA, PARAMETER_DEFAULTS} from "./constants";

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

    const flakes = pickFlakes(results).length

    return {
        total,
        passed,
        failures,
        skipped,
        cancelled,
        flakes,
    }
}

export const pickFlakes = (results: PacketTestEnd[]) => {
    return results
        .filter((r) => r.attemptOf)  // 以前のバージョンの Scenamatica では attemptOf がないので、その場合は除外
        .filter((r) => r.attemptOf! > 1) // 2回以上実行されているものを抽出
        .filter((r) => r.cause === TestResultCause.PASSED // 後に成功したものを抽出（2回以上実行 ＝ 1回目..は失敗）
            || r.cause === TestResultCause.SKIPPED
            || r.cause === TestResultCause.CANCELLED)
        // 最大試行回数のPacketのみを抽出 (name が同じ かつ attemptOf が最大
        .filter((r, index, arr) => {
            const maxAttemptOf = calcMaxAttemptOf(r.scenario.name, arr);

            return r.attemptOf === maxAttemptOf;  // 最大試行回数のPacketのみを抽出
        });
}


const calcMaxAttemptOf = (targetName: string, results: PacketTestEnd[]) => {
    return Math.max(
        ...results
            .filter((r) => r.scenario.name === targetName && r.attemptOf)
            .map((r) => r.attemptOf!)
    );
}


interface Args {
    mcVersion: string
    scenamaticaVersion: string
    serverDir: string
    pluginFile: string
    javaVersion: string
    javaArguments: string[]
    githubToken: string
    graphicalSummary: boolean
    failThreshold: number

    uploadXMLReport: boolean
    reportArtifactName: string

    // PR settings
    pullRequest: boolean
    detailedReportInPRComment: boolean
}

const getArguments = (): Args => {
    return {
        mcVersion: core.getInput("minecraft") || PARAMETER_DEFAULTS.minecraft,
        scenamaticaVersion: core.getInput("scenamatica",) || PARAMETER_DEFAULTS.scenamatica,
        serverDir: core.getInput("server-dir") || PARAMETER_DEFAULTS.serverDir,
        pluginFile: core.getInput("plugin", {required: true}),
        javaVersion: core.getInput("java") || PARAMETER_DEFAULTS.java,
        javaArguments: core.getInput("java-arguments").split(" "),
        githubToken: core.getInput("github-token") || process.env.GITHUB_TOKEN!,
        graphicalSummary: core.getBooleanInput("graphical-summary") || PARAMETER_DEFAULTS.graphicalSummary,
        failThreshold: Number.parseInt(core.getInput("fail-threshold"), 10) || PARAMETER_DEFAULTS.failThreshold,
        uploadXMLReport: core.getBooleanInput("upload-xml-report") || PARAMETER_DEFAULTS.uploadXMLReport,
        reportArtifactName: core.getInput("report-artifact-name") || PARAMETER_DEFAULTS.reportArtifactName,
        pullRequest: core.getBooleanInput("pull-request") || PARAMETER_DEFAULTS.pullRequest,
        detailedReportInPRComment: core.getBooleanInput("detailed-report-in-pr-comment") || PARAMETER_DEFAULTS.detailedReportInPRComment,
    }
}

export const args = getArguments();

const isNoScenamatica = (): boolean => {
    return process.env[ENV_NO_SCENAMATICA] === "true"
}

export const isTestSucceed = (results: PacketTestEnd[]) => {
    const {failures} = extractTestResults(results)
    const threshold = args.failThreshold

    return failures <= threshold
}

export { extractTestResults, Args, isNoScenamatica }
