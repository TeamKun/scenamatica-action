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

const printSummary = async (sessionEnd: PacketSessionEnd) => {
    const {results, finishedAt, startedAt} = sessionEnd

    summary.addRaw(getHeader(false))
    summary.addRaw(getTestSummary(results, startedAt, finishedAt))

    summary.addRaw(getTestResultTable(results))

    await summary.write()
}

let errorHeaderPrinted = false
let errorReportingMessagePrinted = false

const printErrorSummary = async (errorType: string, errorMessage: string, errorStackTrace: string[]) => {
    if (!errorHeaderPrinted) {
        summary.addRaw(getHeader(true))
        errorHeaderPrinted = true
    }

    summary.addRaw(getExceptionString(errorType, errorMessage, errorStackTrace))

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
