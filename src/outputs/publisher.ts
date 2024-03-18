import type  { PacketSessionEnd, PacketScenamaticaError } from "../packets";
import SummaryPrinter from "./summary";
import { publishOutput } from "./action-output";
import type { PullRequestInfo} from "./pull-request/appender";
import {publishPRComment, reportRunning, reportSessionEnd} from "./pull-request/appender";

class OutputPublisher {
    public readonly summaryPrinter: SummaryPrinter

    public constructor() {
        this.summaryPrinter = new SummaryPrinter();
    }

    public async publishSessionEnd(packet: PacketSessionEnd): Promise<void> {
        await this.summaryPrinter.printSummary(packet);
        publishOutput(packet);

        reportSessionEnd(packet);
    }

    public async publishScenamaticaError(packet: PacketScenamaticaError): Promise<void> {
        await this.summaryPrinter.printErrorSummary(packet);
        publishOutput(packet);

        reportError(packet);
    }

    public publishRunning(info: PullRequestInfo): void {
        reportRunning();
        publishPRComment(info) // 即反映
            .catch(console.error);
    }
}

export default OutputPublisher;
