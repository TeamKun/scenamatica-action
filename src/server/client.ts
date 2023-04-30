import type { PacketSessionEnd, PacketSessionStart, PacketTestEnd, PacketTestStart } from "../packets.js"
import { parsePacket, TestResultCause } from "../packets.js"
import { printSessionEnd, printSessionStart, printSummary, printTestEnd, printTestStart } from "../outputs.js"
import { endTests } from "./controller.js"
import {warn} from "../utils";

export const onDataReceived = async (chunkMessage: string) => {
    await processPacket(chunkMessage)
}

const processPacket = async (msg: string) => {
    let packet

    try {
        packet = parsePacket(msg)
    } catch {
        warn(`Failed to parse packet: ${msg}`)

        return
    }

    if (!packet) {
        return
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
    }
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
            sessionStartedAt = packet.startedAt
            printSessionStart(sessionStartedAt, packet.tests.length)

            break
        }

        case "end": {
            const sessionEnd = packet as PacketSessionEnd

            printSessionEnd(sessionEnd)
            await printSummary(sessionEnd)

            const succeed = sessionEnd.tests.every(
                (test) =>
                    test.cause === TestResultCause.PASSED ||
                    test.cause === TestResultCause.SKIPPED ||
                    test.cause === TestResultCause.CANCELLED,
            )

            endTests(succeed)

            break
        }
    }
}
