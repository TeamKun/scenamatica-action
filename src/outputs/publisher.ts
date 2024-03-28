import type {PacketScenamaticaError, PacketSessionEnd} from "../packets";
import SummaryPrinter from "./summary";
import {publishOutput} from "./action-output";
import type {PullRequestInfo} from "./pull-request/appender";
import {publishPRComment, reportRunning, reportSessionEnd, reportError} from "./pull-request/appender";
import {info, warning} from "@actions/core";
import {DefaultArtifactClient} from "@actions/artifact";
import path from "node:path";

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

    public publishRunning(pullRequestInfo: PullRequestInfo): void {
        reportRunning();
        publishPRComment(pullRequestInfo) // 即反映
            .catch(console.error);
    }

    public async publishXMLReports(paths: string[]): Promise<void> {
        if (paths.length === 0) {
            warning("No report to upload found.")
        }

        const artifact = new DefaultArtifactClient()
        const baseDirectory = path.dirname(paths[0])

        const uploadResult = await artifact.uploadArtifact(
            "scenamatica-reports",
            paths,
            baseDirectory
        )
        
        info(`Artifacts uploaded successfully: ${paths.join(", ")} with id ${uploadResult.id!} of size ${uploadResult.size!}`)
    }
}

export default OutputPublisher;
