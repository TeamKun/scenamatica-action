import type {PacketSessionEnd} from "../../packets";
import {
    getExceptionString,
    getFooter,
    getHeader, getReportingMessage,
    getRunningMessage,
    getTestResultTable,
    getTestSummary
} from "../messages";
import { upsertReport} from "./writer";
import type {PacketScenamaticaError} from "../../packets";
import type {GitHub} from "@actions/github/lib/utils";

let headerPrinted = false
let containsError = false
let outMessage = ""


export interface PullRequestInfo {
    octokit: InstanceType<typeof GitHub>;
    owner: string;
    repository: string;
    number: number;
}

export const reportError = (packet: PacketScenamaticaError) => {

    appendHeaderIfNotPrinted()

    outMessage += getExceptionString(packet)
    containsError = true
}

export const reportRunning = () => {
    appendHeaderIfNotPrinted()
    outMessage += getRunningMessage()
}

export const reportSessionEnd = (packet: PacketSessionEnd) => {
    const {results, finishedAt, startedAt} = packet

    appendHeaderIfNotPrinted()

    outMessage += `${getTestSummary(results, startedAt, finishedAt)}
        ${getTestResultTable(results, true)}
    `
}

const appendHeaderIfNotPrinted = () => {
    if (!headerPrinted) {
        outMessage += `${getHeader(false)}`

        headerPrinted = true
    }
}

export const publishPRComment = async (runData: PullRequestInfo) => {
    if (containsError)
        outMessage += getReportingMessage()

    outMessage += getFooter()

    await upsertReport(
        runData.octokit,
        runData.owner,
        runData.repository,
        runData.number,
        outMessage
    )

    outMessage = ""
    containsError = false
    headerPrinted = false
}
