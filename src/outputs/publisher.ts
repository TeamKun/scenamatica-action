import type { PacketSessionEnd,PacketScenamaticaError} from "../packets";
import {printErrorSummary, printSummary} from "./summary";
import {publishOutput} from "./action-output";
import type { PullRequestInfo} from "./pull-request/appender";
import {publishPRComment, reportRunning, reportError, reportSessionEnd} from "./pull-request/appender";

export const publishSessionEnd = async (packet: PacketSessionEnd) => {
    await printSummary(packet)
    publishOutput(packet)

    reportSessionEnd(packet)
}

export const publishScenamaticaError = async (packet: PacketScenamaticaError) => {
    const {exception, message, stackTrace} = packet

    await printErrorSummary(exception, message, stackTrace)
    publishOutput(packet)

    reportError(packet)
}

export const publishRunning = (info: PullRequestInfo) => {
    reportRunning()
    publishPRComment(info)  // 即反映
        .catch(console.error)
}
