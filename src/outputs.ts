import type { PacketSessionEnd, Scenario, TestState } from "./packets.js"
import { TestResultCause} from "./packets.js"
import {getArguments, info, warn} from "./utils.js"
import type {SummaryTableRow} from "@actions/core/lib/summary.js"
import {summary} from "@actions/core";

const MESSAGES_PASSED = [
    ":tada: Congrats! All tests passed! :star2:",
    ":raised_hands: High-five! You nailed all the tests! :tada::tada:",
    ":confetti_ball: Hooray! Everything's working perfectly! :tada::confetti_ball:",
    ":100: Perfect score! All tests passed with flying colors! :rainbow::clap:",
    ":thumbsup: Great job! All tests passed without a hitch! :rocket::star2:",
    ":metal: Rock on! All tests passed flawlessly! :guitar::metal:",
    ":partying_face: Celebrate good times! All tests passed with flying colors! :tada::confetti_ball::balloon:",
    ":muscle: You crushed it! All tests passed with ease! :fire::muscle:",
    ":1st_place_medal: Gold medal performance! All tests passed with flying colors! :medal::star2:",
    ":champagne: Pop the champagne! All tests passed, time to celebrate! :champagne::tada:"
];

const MESSAGES_NO_TESTS = [
    "Alright, who forgot to write tests? :face_with_raised_eyebrow:",
    "No tests? Time to break out the crystal ball. :crystal_ball:",
    "Tests? Who writes tests? :person_shrugging:",
    "No tests found. Did they run away? :man_running: :woman_running:",
    "No tests, no glory. :trophy:",
    "Tests? We don't need no stinkin' tests! :shushing_face:",
    "No tests? I guess we'll just have to wing it. :eagle:",
    "You get a test, and you get a test! Everybody gets a test! :gift: :tada:",
    "No tests? That's unpossible! :dizzy_face:",
    "Tests make the code go round. :carousel_horse:"
];

const MESSAGES_FAILED = [
    "Oops! Something went wrong! :scream_cat:",
    "Oh no! The tests have betrayed us! :scream:",
    "Houston, we have a problem. :rocket:",
    "Looks like we have some debugging to do. :beetle:",
    "Failures? More like opportunities to improve! :muscle:",
    "This is not the result we were looking for. :confused:",
    "Looks like we need to rethink our strategy. :thinking:",
    "Don't worry, we'll get 'em next time! :sunglasses:",
    "Keep calm and debug on. :female_detective:",
    "The only way is up from here! :rocket:"
];


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
            return ":no_entry:"
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

const printSummary = async (sessionEnd: PacketSessionEnd) => {
    const {results, finishedAt, startedAt} = sessionEnd
    const elapsed = `${Math.ceil((finishedAt - startedAt) / 1000)} sec`
    const total = results.length
    const passed = results.filter((t) => t.cause === TestResultCause.PASSED).length

    const failures = results.filter(
        (t) =>
            !(
                t.cause === TestResultCause.PASSED ||
                t.cause === TestResultCause.SKIPPED ||
                t.cause === TestResultCause.CANCELLED
            ),
    ).length

    const skipped = results.filter((t) => t.cause === TestResultCause.SKIPPED).length

    let messageSource;

    if (total === passed + skipped) messageSource = MESSAGES_PASSED
    else if (failures === 0) messageSource = MESSAGES_NO_TESTS
    else messageSource = MESSAGES_FAILED

    const summaryText = messageSource[Math.floor(Math.random() * messageSource.length)]

    summary.addHeading("Scenamatica", 1)
    summary.addHeading("Summary", 2)
    summary.addHeading(`${summaryText}`, 4)
    summary.addBreak()
    summary.addRaw(`Tests run: ${total}, Failures: ${failures}, Skipped: ${skipped}, Time elapsed: ${elapsed}`)
    summary.addHeading("Details", 2)

    const table: SummaryTableRow[] = [
        [
            {
                data: " ",
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
                data: "Finished at",
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

    for (const t of results) {
        const testElapsed = `${Math.ceil((t.finishedAt - t.startedAt) / 1000)} sec`
        const emoji = getEmojiForCause(t.cause)
        const { name } = t.scenario
        const { description } = t.scenario
        const startedAtStr = new Date(t.startedAt).toLocaleString()
        const finishedAtStr = new Date(t.finishedAt).toLocaleString()

        table.push([
            { data: emoji },
            { data: name },
            { data: t.cause.toString() },
            { data: t.state.toString() },
            { data: startedAtStr },
            { data: finishedAtStr },
            { data: testElapsed },
            { data: description },
        ])
    }

    summary.addTable(table)

    printLicense()
    await summary.write()
}

const printErrorSummary = async (errorType: string, errorMessage: string, errorStackTrace: string[]) => {
    summary.addHeading("Scenamatica", 1)
    summary.addHeading("Summary", 2)
    summary.addHeading(":no_entry: ERROR!!", 4)
    summary.addBreak()
    summary.addRaw("An unexpected error occurred while running the server and Scenamatica daemon.")

    summary.addHeading("Details", 2)

    const errorTexts = [
        "An unexpected exception has occurred while running Scenamatica daemon:",
        `${errorType}: ${errorMessage}`,
        ...errorStackTrace.map((s) => `    at ${s}`),
    ]

    summary.addCodeBlock(errorTexts.join("\n"), "text")

    summary.addHeading("Reporting bugs", 2)
    summary.addRaw("If you think this is a bug, please report it to ")
        .addLink("Scenamatica", "https://github.com/TeamKun/Scenamatica/issues")
        .addRaw(" with contents of this error message, above stack trace and below environment information.")
        .addBreak()

    const runArgs = getArguments()

    const envInfo = [
        "+ Versions:",
        `  - Scenamatica: ${runArgs.scenamaticaVersion}`,
        `  - Minecraft: ${runArgs.mcVersion}`,
        `  - Java: ${runArgs.javaVersion}`,
        `  - Node.js: ${process.version}`,
        "+ Runner:",
        `  - OS: ${process.platform}`,
        `  - Arch: ${process.arch}`,
    ]

    summary.addDetails("Environment Information", envInfo.join("\n"))


    printLicense()
    await summary.write()
}

const printLicense = () => {
    summary.addHeading("License", 2)
    summary
        .addRaw("This test report has been generated by ")
        .addLink("Scenamatica", "https://github.com/TeamKUN/Scenamatica")
        .addRaw(" and licensed under ")
        .addLink("MIT License", "https://github.com/TeamKUN/Scenamatica/blob/main/LICENSE")
        .addRaw(".")
    summary.addBreak()
    summary.addRaw("You can redistribute it and/or modify it under the terms of the MIT License.")
}

export { printTestStart, printTestEnd, printSessionStart, printSessionEnd, printSummary, printErrorSummary }
