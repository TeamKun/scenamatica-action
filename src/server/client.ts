import type { PacketSessionEnd, PacketSessionStart, PacketTestEnd, PacketTestStart ,PacketScenamaticaError} from "../packets.js"
import { parsePacket, TestResultCause} from "../packets.js"
import {
    printErrorSummary,
    printSessionEnd,
    printSessionStart,
    printSummary,
    printTestEnd,
    printTestStart
} from "../outputs.js"
import { endTests } from "./controller.js"
import {info} from "../utils";

let incomingBuffer: string | undefined

export const onDataReceived = async (chunkMessage: string) => {
    incomingBuffer = incomingBuffer ? incomingBuffer + chunkMessage : chunkMessage

    while (incomingBuffer && incomingBuffer.includes("\n")) {
        const messages: string[] = incomingBuffer.split("\n")

        if (!await processPacket(messages[0]))
            info(messages[0])
        incomingBuffer = messages.slice(1).join("\n") || undefined
    }
}

const processPacket = async (msg: string) => {
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
            await processErrorPacket(packet as PacketScenamaticaError)  // general ジャンルは、エラーのみしかない
        }
    }

    return true
}

const processTestsPacket = (packet: PacketTestEnd | PacketTestStart) => {
    switch (packet.type) {
        case "start": {
            const test = packet as PacketTestStart

            printTestStart(test.scenario)

            break
        }

        case "end": {
            const testEnd = packet as PacketTestEnd

            printTestEnd(testEnd.scenario.name, testEnd.state, testEnd.cause, testEnd.startedAt, testEnd.finishedAt)
        }
    }
}

let sessionStartedAt: number | undefined

const processSessionPackets = async (packet: PacketSessionEnd | PacketSessionStart) => {
    switch (packet.type) {
        case "start": {
            const sessionStart = packet as PacketSessionStart

            sessionStartedAt = packet.startedAt

            printSessionStart(sessionStartedAt, sessionStart.tests.length)

            break
        }

        case "end": {
            const sessionEnd = packet as PacketSessionEnd

            printSessionEnd(sessionEnd)
            await printSummary(sessionEnd)

            const succeed = (sessionEnd.results ).every(
                (test) =>
                    test.cause === TestResultCause.PASSED ||
                    test.cause === TestResultCause.SKIPPED ||
                    test.cause === TestResultCause.CANCELLED
            )

            endTests(succeed)

            break
        }
    }
}

const processErrorPacket = async (packet: PacketScenamaticaError) => {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const {exception, message, stackTrace} = packet

    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    await printErrorSummary(exception, message, stackTrace)

    endTests(false)
}
