import type { PacketSessionEnd} from "../packets";
import {PacketScenamaticaError, TestResultCause} from "../packets";
import {setOutput} from "@actions/core";


export const publishOutput = (packet: PacketScenamaticaError | PacketSessionEnd) => {
    if (packet instanceof PacketScenamaticaError) {
        publishError(packet)
    } else {
        publishEnd(packet);
    }
}

const publishError = (packet: PacketScenamaticaError) => {
    const {exception, message} = packet

    setOutput("success", false)
    setOutput("runner-error-type", exception)
    setOutput("runner-error-message", message)
}

const publishEnd = (packet: PacketSessionEnd) => {
    const {results} = packet
    const all = results.length
    const passed = results.filter((t) => t.cause === TestResultCause.PASSED).length
    const skipped = results.filter((t) => t.cause === TestResultCause.SKIPPED).length
    const cancelled = results.filter((t) => t.cause === TestResultCause.CANCELLED).length
    const failed = all - passed - skipped - cancelled

    setOutput("success", failed === 0)
    setOutput("tests", all)
    setOutput("tests-passes", passed)
    setOutput("tests-failures", failed)
    setOutput("tests-skips", skipped)
    setOutput("tests-cancels", cancelled)
}
