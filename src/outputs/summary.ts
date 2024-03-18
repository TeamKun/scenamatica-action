import type { PacketSessionEnd } from "../packets";
import { summary } from "@actions/core";
import {
    getExceptionString,
    getFooter,
    getHeader,
    getReportingMessage,
    getTestResultTable,
    getTestSummary,
} from "./messages";
import type { PacketScenamaticaError } from "../packets";
import { generateGraphicalSummary } from "./graphical-summary";
import { getArguments } from "../utils";

class SummaryPrinter {
    private errorHeaderPrinted = false;

    private errorReportingMessagePrinted = false;

    public async printSummary(sessionEnd: PacketSessionEnd): Promise<void> {
        const { results, finishedAt, startedAt } = sessionEnd;

        summary.addRaw(getHeader(false));
        summary.addRaw(getTestSummary(results, startedAt, finishedAt));

        summary.addRaw(getTestResultTable(results, true));

        if (getArguments().graphicalSummary)
            summary.addRaw(generateGraphicalSummary(sessionEnd));

        await summary.write();
    }

    public async printErrorSummary(packet: PacketScenamaticaError): Promise<void> {
        if (!this.errorHeaderPrinted) {
            summary.addRaw(getHeader(true));
            this.errorHeaderPrinted = true;
        }

        summary.addRaw(getExceptionString(packet));

        if (!this.errorReportingMessagePrinted) {
            summary.addRaw(getReportingMessage());
            this.errorReportingMessagePrinted = true;
        }

        await summary.write();
    }

    public async printFooter(): Promise<void> {
        summary.addRaw(getFooter());

        await summary.write();
    }
}

export default SummaryPrinter;
