import type {
    PacketScenamaticaError,
    PacketSessionEnd,
    PacketSessionStart,
    PacketTestEnd,
    PacketTestStart
} from "../packets.js"
import {parsePacket} from "../packets.js"
import {error, info} from "@actions/core";
import {
    publishRunning,
    publishScenamaticaError,
    publishSessionEnd
} from "../outputs";
import {logSessionEnd, logSessionStart, logTestEnd, logTestStart} from "../logging";
import type {PullRequestInfo} from "../outputs/pull-request";
import {endTests} from "./controller";
import {isTestSucceed} from "../utils";
import {publishPRComment} from "../outputs/pull-request";

let incomingBuffer: string | undefined
let alive = true
let prInfo: PullRequestInfo | undefined

export const initPullRequest = (pi: PullRequestInfo) => {
    prInfo = pi

    publishRunning(pi)
}

export const onDataReceived = async (chunkMessage: string) => {
    incomingBuffer = incomingBuffer ? incomingBuffer + chunkMessage : chunkMessage

    while (incomingBuffer && incomingBuffer.includes("\n")) {
        const messages: string[] = incomingBuffer.split("\n")

        incomingBuffer = messages.slice(1).join("\n") || undefined
        if (!await processPacket(messages[0]))
            info(messages[0])
    }
}

export const kill = () => {
    alive = false
}

const processPacket = async (msg: string) => {
    if (!alive) {
        return false
    }

    let packet

    try {
        packet = parsePacket(msg)
    } catch {
        return false
    }

    if (!packet) {
        return false
    }

    switch (packet.genre) {
        case "session": {
            await processSessionPackets(packet as PacketSessionEnd | PacketSessionStart)

            break
        }

        case "test": {
            processTestsPacket(packet as PacketTestEnd | PacketTestStart)

            break
        }

        case "general": {
            if (packet.type !== "error") {
                return false // general ジャンルは、エラーのみしかない
            }

            const errorPacket = packet as PacketScenamaticaError

            error(`An error occurred in Scenamatica: ${errorPacket.exception}: ${errorPacket.message}`)
            await publishScenamaticaError(errorPacket)
            if (prInfo)
                await publishPRComment(prInfo)

            await endTests(false)

            break
        }
    }

    return true
}

const processTestsPacket = (packet: PacketTestEnd | PacketTestStart) => {
    switch (packet.type) {
        case "start": {
            logTestStart(packet.scenario)

            break
        }

        case "end": {
            const endPacket = packet as PacketTestEnd

            logTestEnd(
                packet.scenario.name,
                endPacket.state,
                endPacket.cause,
                endPacket.startedAt,
                endPacket.finishedAt
            )

            break
        }
    }
}

const processSessionPackets = async (packet: PacketSessionEnd | PacketSessionStart) => {
    switch (packet.type) {
        case "start": {
            const sessionStart = packet as PacketSessionStart

            logSessionStart(packet.startedAt, sessionStart.tests.length)

            break
        }

        case "end": {
            const sessionEnd = packet as PacketSessionEnd

            logSessionEnd(sessionEnd)
            await publishSessionEnd(sessionEnd)
            if (prInfo)
                await publishPRComment(prInfo)

            await endTests(isTestSucceed(sessionEnd.results))

            break
        }
    }
}

