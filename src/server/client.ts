import {
    PacketSessionEnd,
    PacketSessionStart,
    PacketTestEnd,
    PacketTestStart,
    parsePacket,
    TestResultCause
} from "../packets"
import {printSessionEnd, printSessionStart, printSummary, printTestEnd, printTestStart} from "../outputs"
import test from "node:test";
import {endTests} from "./controller";

let message: string | null = null
export async function onDataReceived(chunkMessage: any) {
    message = message ? message + chunkMessage : chunkMessage

    while (message && message.includes('\n')) {
        const messages = message.split('\n')
        await processPacket(messages[0])
        message = messages.slice(1).join('\n') || null
    }
}

async function processPacket(msg: string) {
    let packet
    try {
        packet = parsePacket(msg)
    }
    catch (e) {
        console.warn(`Failed to parse packet: ${msg}`)
        return
    }

    if (!packet) {
        return
    }

    switch (packet.genre) {
        case "session":
            await processSessionPackets(packet as PacketSessionStart | PacketSessionEnd)
            break
        case "test":
            processTestsPacket(packet as PacketTestStart | PacketTestEnd)
            break
    }
}

function processTestsPacket(packet: PacketTestStart | PacketTestEnd) {
    switch (packet.type) {
        case "start":
            const test = packet as PacketTestStart
            printTestStart(test.scenario)
            break
        case "end":
            const testEnd = packet as PacketTestEnd

            printTestEnd(
                testEnd.scenario.name,
                testEnd.state,
                testEnd.cause,
                testEnd.startedAt,
                testEnd.finishedAt
            )
    }
}

let sessionStartedAt: number | null = null
async function processSessionPackets(packet: PacketSessionStart | PacketSessionEnd) {
    switch (packet.type) {
        case "start":
            sessionStartedAt = packet.startedAt
            printSessionStart(sessionStartedAt, packet.tests.length)
            break
        case "end":
            const sessionEnd = packet as PacketSessionEnd
            printSessionEnd(sessionEnd)
            await printSummary(sessionEnd)
            const succeed = sessionEnd.tests.every(test =>
                test.cause === TestResultCause.PASSED || test.cause === TestResultCause.SKIPPED || test.cause === TestResultCause.CANCELLED
            )

            await endTests(succeed)
            break
    }
}
