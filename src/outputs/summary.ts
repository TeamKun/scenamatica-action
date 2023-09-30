import type {PacketSessionEnd} from "../packets"
import {summary} from "@actions/core";
import {
    getExceptionString,
    getFooter,
    getHeader,
    getReportingMessage,
    getTestResultTable,
    getTestSummary
} from "./messages";
import type {PacketScenamaticaError} from "../packets";
import {generateGraphicalSummary} from "./graphical-summary";
import {getArguments} from "../utils";

const printSummary = async (sessionEnd: PacketSessionEnd) => {
    const {results, finishedAt, startedAt} = sessionEnd

    summary.addRaw(getHeader(false))
    summary.addRaw(getTestSummary(results, startedAt, finishedAt))

    if (getArguments().graphicalSummary)
    {
        console.log("Generating graphical summary...")
        summary.addRaw(generateGraphicalSummary(sessionEnd))
    }

    summary.addRaw(getTestResultTable(results, true))

    await summary.write()
}

let errorHeaderPrinted = false
let errorReportingMessagePrinted = false

const printErrorSummary = async (packet: PacketScenamaticaError) => {
    if (!errorHeaderPrinted) {
        summary.addRaw(getHeader(true))
        errorHeaderPrinted = true
    }

    summary.addRaw(getExceptionString(packet))

    if (!errorReportingMessagePrinted) {
        summary.addRaw(getReportingMessage())
        errorReportingMessagePrinted = true
    }

    await summary.write()
}

const printFooter = async () => {
    summary.addRaw(getFooter())

    await summary.write()
}

export { printSummary, printErrorSummary, printFooter }
