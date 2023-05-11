import type {PacketSessionEnd, Scenario, TestState} from "./packets";
import { TestResultCause} from "./packets";
import {endGroup, info, startGroup, warning} from "@actions/core";

export const logTestStart = (scenario: Scenario): void => {
    startGroup(`Test: ${scenario.name}`)
    info(`Starting test: ${scenario.name} (${scenario.description ?? "(No description provided)"})`)
}

export const logTestEnd = (
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
            warning(`${emoji} The test ${name} is failed with state ${state} in ${elapsed}.`)

            break
        }
    }

    endGroup()
}

export const getEmojiForCause = (cause: TestResultCause): string => {
    switch (cause) {
        case TestResultCause.PASSED: {
            return "✔"
        }

        case TestResultCause.SKIPPED: {
            return "➔"
        }

        case TestResultCause.CANCELLED: {
            return ":no_entry:"
        }

        default: {
            return "❌"
        }
    }
}

export const logSessionStart = (startedAt: number, tests: number): void => {
    info("--------------------------------------")
    info(" T E S T S")
    info("--------------------------------------")
    info(`The session is started at ${startedAt}, ${tests} tests are marked to be run.`)
}

export const logSessionEnd = (sessionEnd: PacketSessionEnd): void => {
    const elapsed = `${Math.ceil((sessionEnd.finishedAt - sessionEnd.startedAt) / 1000)} sec`
    const {results} = sessionEnd
    const total = results.length

    const failures = results.filter(
        (t) =>
            !(
                t.cause === TestResultCause.PASSED ||
                t.cause === TestResultCause.SKIPPED ||
                t.cause === TestResultCause.CANCELLED
            ),
    ).length

    const skipped = results.filter((t) => t.cause === TestResultCause.SKIPPED).length

    info(`\nResults:\n`)
    info(`Tests run: ${total}, Failures: ${failures}, Skipped: ${skipped}, Time elapsed: ${elapsed}\n`)
}

