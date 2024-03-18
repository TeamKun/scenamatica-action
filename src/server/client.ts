import type { PacketSessionEnd, PacketSessionStart, PacketTestEnd, PacketTestStart, PacketScenamaticaError} from "../packets";
import { parsePacket } from "../packets.js";
import { error, info } from "@actions/core";
import { logSessionEnd, logSessionStart, logTestEnd, logTestStart } from "../logging";
import { isTestSucceed } from "../utils";
import type { PullRequestInfo} from "../outputs/pull-request/appender";
import {publishPRComment} from "../outputs/pull-request/appender";
import type OutputPublisher from "../outputs/publisher";

class ScenamaticaPacketProcessor {
    private readonly publisher: OutputPublisher

    private onEndTests: (succeed: boolean) => Promise<void>;

    private incomingBuffer: string | undefined;

    private alive = true;

    private prInfo: PullRequestInfo | undefined;

    public constructor(publisher: OutputPublisher, onEndTests: (succeed: boolean) => Promise<void>) {
        this.publisher = publisher
        this.onEndTests = onEndTests
    }

    public enablePullRequestMode(pi: PullRequestInfo): void {
        this.prInfo = pi;
        this.publisher.publishRunning(pi)
    }

    public async onDataReceived(chunkMessage: string): Promise<void> {
        this.incomingBuffer = this.incomingBuffer ? this.incomingBuffer + chunkMessage : chunkMessage;

        while (this.incomingBuffer && this.incomingBuffer.includes("\n")) {
            const messages: string[] = this.incomingBuffer.split("\n");

            this.incomingBuffer = messages.slice(1).join("\n") || undefined;

            if (!await this.processPacket(messages[0])) {
                info(messages[0]);
            }
        }
    }

    public kill(): void {
        this.alive = false;
    }

    private async processPacket(msg: string): Promise<boolean> {
        if (!this.alive) {
            return false;
        }

        let packet;

        try {
            packet = parsePacket(msg);
        } catch {
            return false;
        }

        if (!packet) {
            return false;
        }

        switch (packet.genre) {
            case "session": {
                await this.processSessionPackets(packet as PacketSessionEnd | PacketSessionStart);

                break;
            }

            case "test": {
                this.processTestsPacket(packet as PacketTestEnd | PacketTestStart);

                break;
            }

            case "general": {
                if (packet.type !== "error") {
                    return false; // general ジャンルは、エラーのみしかない
                }

                const errorPacket = packet as PacketScenamaticaError;
                const message = errorPacket.message || "null";

                error(`An error occurred in Scenamatica: ${errorPacket.exception}: ${message}`);
                await this.publisher.publishScenamaticaError(errorPacket)

                if (this.prInfo) {
                    await publishPRComment(this.prInfo);
                }

                await this.onEndTests(false)

                break;
            }
        }

        return true;
    }

    private processTestsPacket(packet: PacketTestEnd | PacketTestStart): void {
        switch (packet.type) {
            case "start": {
                logTestStart(packet.scenario);

                break;
            }

            case "end": {
                const endPacket = packet as PacketTestEnd;

                logTestEnd(
                    packet.scenario.name,
                    endPacket.state,
                    endPacket.cause,
                    endPacket.startedAt,
                    endPacket.finishedAt
                );

                break;
            }
        }
    }

    private async processSessionPackets(packet: PacketSessionEnd | PacketSessionStart): Promise<void> {
        switch (packet.type) {
            case "start": {
                const sessionStart = packet as PacketSessionStart;

                logSessionStart(packet.startedAt, sessionStart.tests.length);

                break;
            }

            case "end": {
                const sessionEnd = packet as PacketSessionEnd;

                logSessionEnd(sessionEnd);
                await this.publisher.publishSessionEnd(sessionEnd)

                if (this.prInfo) {
                    await publishPRComment(this.prInfo);
                }

                await this.onEndTests(isTestSucceed(sessionEnd.results));

                break;
            }
        }
    }
}

export default ScenamaticaPacketProcessor;
