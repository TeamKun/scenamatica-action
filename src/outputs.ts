import type { PacketSessionEnd, Scenario, TestState } from "./packets.js"
import { TestResultCause } from "./packets.js"
import { info, warn } from "./utils.js"
import * as core from "@actions/core"
import type {SummaryTableRow} from "@actions/core/lib/summary.js"

const printTestStart = (scenario: Scenario): void => {
    info(`Starting test: ${scenario.name} (${scenario.description})`)
}

const printTestEnd = (
    name: string,
    state: TestState,
    cause: TestResultCause,
    startedAt: number,
    finishedAt: number,
): void => {
    const elapsed = `${finishedAt - startedAt} ms`
    const emoji = getEmojiForCause(cause)

    switch (cause) {
        case TestResultCause.CANCELLED: {
            info(`${emoji} The test ${name} is cancelled with state ${state} in ${elapsed}.`)

            break
        }

        case TestResultCause.PASSED: {
            info(`${emoji} The test ${name} is passed with state ${state} in ${elapsed}.`)

            break
        }

        case TestResultCause.SKIPPED: {
            info(`${emoji} The test ${name} is skipped with state ${state} in ${elapsed}.`)

            break
        }

        default: {
            warn(`${emoji} The test ${name} is failed with state ${state} in ${elapsed}.`)

            break
        }
    }
}

const getEmojiForCause = (cause: TestResultCause): string => {
    switch (cause) {
        case TestResultCause.PASSED: {
            return "✔"
        }

        case TestResultCause.SKIPPED: {
            return "➔"
        }

        case TestResultCause.CANCELLED: {
            return "⚠"
        }

        default: {
            return "❌"
        }
    }
}

const printSessionStart = (startedAt: number, tests: number): void => {
    info("--------------------------------------")
    info(" T E S T S")
    info("--------------------------------------")
    info(`The session is started at ${startedAt}, ${tests} tests are marked to be run.`)
}

const printSessionEnd = (sessionEnd: PacketSessionEnd): void => {
    const elapsed = `${Math.ceil((sessionEnd.finishedAt - sessionEnd.startedAt) / 1000)} sec`
    const total = sessionEnd.tests.length

    const failures = sessionEnd.tests.filter(
        (t) =>
            !(
                t.cause === TestResultCause.PASSED ||
                t.cause === TestResultCause.SKIPPED ||
                t.cause === TestResultCause.CANCELLED
            ),
    ).length

    const skipped = sessionEnd.tests.filter((t) => t.cause === TestResultCause.SKIPPED).length

    info(`\nResults:\n`)
    info(`Tests run: ${total}, Failures: ${failures}, Skipped: ${skipped}, Time elapsed: ${elapsed}\n`)
}

const printSummary = async (sessionEnd: PacketSessionEnd) => {
    const elapsed = `${Math.ceil((sessionEnd.finishedAt - sessionEnd.startedAt) / 1000)} sec`
    const total = sessionEnd.tests.length
    const passed = sessionEnd.tests.filter((t) => t.cause === TestResultCause.PASSED).length

    const failures = sessionEnd.tests.filter(
        (t) =>
            !(
                t.cause === TestResultCause.PASSED ||
                t.cause === TestResultCause.SKIPPED ||
                t.cause === TestResultCause.CANCELLED
            ),
    ).length

    const skipped = sessionEnd.tests.filter((t) => t.cause === TestResultCause.SKIPPED).length

    let summaryText

    if (total === passed + skipped) summaryText = "It's all green! 🎉"
    else if (failures === 0) summaryText = "Only skipped tests! 🤔"
    else summaryText = "Some tests are failed! 😢"

    const { summary } = core

    summary.addHeading("Scenamatica", 1)
    summary.addHeading("Summary", 2)
    summary.addRaw(summaryText)
    summary.addBreak()
    summary.addRaw(`Tests run: ${total}, Failures: ${failures}, Skipped: ${skipped}, Time elapsed: ${elapsed}`)
    summary.addHeading("Details", 2)

    const table: SummaryTableRow[] = [
        [
            {
                data: "x",
                header: true,
            },
            {
                data: "Test",
                header: true,
            },
            {
                data: "Cause",
                header: true,
            },
            {
                data: "State",
                header: true,
            },
            {
                data: "Started at",
                header: true,
            },
            {
                data: "Elapsed",
                header: true,
            },
            {
                data: "Test Description",
                header: true,
            },
        ],
    ]

    for (const t of sessionEnd.tests) {
        const testElapsed = `${Math.ceil((t.finishedAt - t.startedAt) / 1000)} sec`
        const emoji = getEmojiForCause(t.cause)
        const { name } = t.scenario
        const { description } = t.scenario

        table.push([
            { data: emoji },
            { data: name },
            { data: t.cause.toString() },
            { data: t.state.toString() },
            { data: t.startedAt.toString() },
            { data: testElapsed },
            { data: description },
        ])
    }

    summary.addTable(table)

    summary.addHeading("License", 2)
    summary
        .addRaw("This test report is generated by ")
        .addLink("Scenamatica", "https://github.com/TeamKUN/Scenaamtica")
        .addRaw(" and licensed under ")
        .addLink("MIT License", "https://github.com/TeamKUN/Scenaamtica/blob/main/LICENSE")
        .addRaw(".")
    summary.addBreak()
    summary.addRaw("You can redistribute it and/or modify it under the terms of the MIT License.")

    await summary.write()
}

export { printTestStart, printTestEnd, printSessionStart, printSessionEnd, printSummary }
