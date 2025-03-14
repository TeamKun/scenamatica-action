import {args, extractTestResults} from "../utils";
import type {PacketTestEnd} from "../packets";
import {getEmojiForCause} from "../logging";
import type {PacketScenamaticaError} from "../packets";
import {BUG_REPORT_URL} from "../constants";

const MESSAGES_PASSED = [
    ":tada: Congrats! All tests passed! :star2:",
    ":raised_hands: High-five! You nailed all the tests! :tada::tada:",
    ":confetti_ball: Hooray! Everything's working perfectly! :tada::confetti_ball:",
    ":100: Perfect score! All tests passed with flying colors! :rainbow::clap:",
    ":thumbsup: Great job! All tests passed without a hitch! :rocket::star2:",
    ":metal: Rock on! All tests passed flawlessly! :guitar::metal:",
    ":partying_face: Celebrate good times! All tests passed with flying colors! :tada::confetti_ball::balloon:",
    ":muscle: You crushed it! All tests passed with ease! :fire::muscle:",
    ":1st_place_medal: Gold medal performance! All tests passed with flying colors! :1st_place_medal::star2:",
    ":champagne: Pop the champagne! All tests passed, time to celebrate! :champagne::tada:"
];

const MESSAGES_NO_TESTS = [
    "Alright, who forgot to write tests? :raised_eyebrow:",
    "No tests? Time to break out the crystal ball. :crystal_ball:",
    "Tests? Who writes tests? :person_shrugging:",
    "No tests found. Did they run away? :running_man: :running_woman:",
    "No tests, no glory. :trophy:",
    "Tests? We don't need no stinkin' tests! :shushing_face:",
    "No tests? I guess we'll just have to wing it. :eagle:",
    "You get a test, and you get a test! Everybody gets a test! :gift: :tada:",
    "No tests? That's impossible! :dizzy_face:",
    "Tests make the code go round. :carousel_horse:"
];

const MESSAGES_FAILED = [
    "Oops! Something went wrong! :scream_cat:",
    "Oh no! The tests have betrayed us! :scream:",
    "Houston, we have a problem. :rocket:",
    "Looks like we have some debugging to do. :bug:",
    "Failures? More like opportunities to improve! :muscle:",
    "This is not the result we were looking for. :confused:",
    "Looks like we need to rethink our strategy. :thinking:",
    "Don't worry, we'll get 'em next time! :sunglasses:",
    "Keep calm and debug on. :female_detective:",
    "The only way is up from here! :rocket:"
];

const MESSAGES_PASSED_WITH_THRESHOLD = [
    "Tests passed, but some are being rebellious. Debug mode: ON! :microscope:",
    "Almost there! Some tests failed, but hey, progress is progress! :turtle:",
    "Good news: most tests passed. Bad news: a few had different plans. Let's fix 'em! :hammer:",
    "We're on the right track, but some tests are playing hard to get. Challenge accepted! :muscle:",
    "Tests went well overall, but we have a few stubborn failures. Time for some gentle persuasion! :wrench:",
    "Success with a side of failures. It's like a bittersweet symphony. Let's sweeten it up! :musical_note:",
    "We're soaring high, but some tests got left behind. Time to reel them back in! :fishing_pole_and_fish:",
    "Great progress, but we've got some test gremlins causing trouble. Let's send them packing! :imp:",
    "Victory is ours, with a sprinkle of defeat. Let's conquer those pesky failures! :crossed_swords:",
    "We're almost there, but a few tests are being rebellious. Let's bring them back to the flock! :sheep:"
];

export const getHeader = (isError: boolean) => {
    const result = [
        wrap("h1", `Scenamatica for Minecraft ${args.mcVersion}`),
        wrap("h2", "Summary"),
        "<hr />"
    ]

    if (isError) {
        result.push(
            wrap("h4", ":no_entry: ERROR!!"),
            wrap("p", "An unexpected error occurred while running the server and Scenamatica daemon."),
            wrap("h2", "Error details")
        )
    }

    return joinLine(...result)
}

export const getRunningMessage = () => {
    const messages = [
        wrap("h4", ":hourglass_flowing_sand: Hey there! :wave: We're currently testing your plugin."),
        wrap("p", "The testing process may take some time, but we'll update this message once it's complete.")
    ]

    return joinLine(...messages)
}

export const getTestSummary = (results: PacketTestEnd[], startedAt: number, finishedAt: number) => {
    const elapsed = (finishedAt - startedAt) / 1000

    const {
        total,
        passed,
        failures,
        skipped,
        cancelled,
        flakes
    } = extractTestResults(results)


    return joinLine(
        getSummaryHeader(total, elapsed, passed, failures, skipped, cancelled, flakes),
        "<hr />"
    )
}

export const getTestResultTable = (results: PacketTestEnd[], minimize = false) => {
    const header = joinLine(
        wrap("h2", "Details"),
        wrap("thead", joinLine(
                wrap("tr", joinLine(
                    wrap("th", " "),
                    wrap("th", "Test"),
                    wrap("th", "Cause"),
                    wrap("th", "State"),
                    wrap("th", "Started at"),
                    wrap("th", "Finished at"),
                    wrap("th", "Elapsed"),
                    wrap("th", "Test description")
                ))
            )
        ))

    const body = wrap("tbody", joinLine(...results.map((result) => {
            const {
                cause,
                state,
                scenario,
                startedAt,
                finishedAt
            } = result

            const emoji = getEmojiForCause(cause)
            const { name } = scenario
            const startedAtStr = new Date(startedAt).toLocaleString()
            const finishedAtStr = new Date(finishedAt).toLocaleString()
            const testElapsed = `${Math.ceil((finishedAt - startedAt) / 1000)} sec`
            const description = scenario.description || "No description"

            return wrap("tr", joinLine(
                wrap("td", emoji),
                wrap("td", name),
                wrap("td", cause),
                wrap("td", state),
                wrap("td", startedAtStr),
                wrap("td", finishedAtStr),
                wrap("td", testElapsed),
                wrap("td", description)
            ))
        }))
    )

    const table = wrap("table", joinLine(header, body))

    if (minimize)
        return wrap("details", joinLine(
            wrap("summary", "Full test results"),
            table
        ))

    return table
}

const getSummaryHeader = (total: number, elapsed: number, passed: number, failures: number, skipped: number,
                          cancelled: number, flakes: number) => {
    const threshold = args.failThreshold

    let messageSource: string[]

    if (total === passed + skipped) messageSource = MESSAGES_PASSED
    else if (failures === 0) messageSource = MESSAGES_NO_TESTS
    else if (failures <= threshold) messageSource = MESSAGES_PASSED_WITH_THRESHOLD
    else messageSource = MESSAGES_FAILED

    const summaryText = messageSource[Math.floor(Math.random() * messageSource.length)]

    const countTexts: string[] = [
        `Tests run: ${total}`,
        `Failures: ${failures}`,
        `Skipped: ${skipped}`,
        `Cancelled: ${cancelled}`,
    ]
    
    if (flakes > 0) {
        countTexts.push(`Flakes: ${flakes}`)
    }
    
    countTexts.push(`Time elapsed: ${elapsed} sec`)
    
    return joinLine(
        wrap("h4", summaryText),
        "<br />",
        wrap("p", join(", ", ...countTexts))
    )
}

export const getExceptionString = (packet: PacketScenamaticaError) => {
    return wrap("pre", wrap("code", joinLine(
                "An unexpected error has occurred while running Scenamatica daemon:",
                getErrorAndStacktrace(packet)
    )))
}

const getErrorAndStacktrace = (packet: PacketScenamaticaError) => {
    const {exception, message, stackTrace, causedBy } = packet

    let causedByString;

    if (causedBy) {
        causedByString = joinLine(`Caused by: ${getErrorAndStacktrace(causedBy)}`)
    }

    return joinLine(
        `${exception}: ${message}`,
        ...stackTrace.map((s) => `    at ${s}`),
        causedByString || ""
    )

}

export const getReportingMessage = () => {
    return joinLine(
        wrap("h2", "Reporting bugs"),
        wrap("p", combine(
            "If you believe this is a bug, please report it to ",
            wrap("a", "Scenamatica", { href: BUG_REPORT_URL }),
            " along with the contents of this error message, the above stack trace, and the environment information listed below."
        )),
        getEnvInfoMessage()
    )
}

export const getFooter = () => {
    return joinLine(
        "<hr />",
        getLicenseMessage()
    )
}

const getEnvInfoMessage = () => {

    const envInfo = [
        "+ Versions:",
        `  - Scenamatica: ${args.scenamaticaVersion}`,
        `  - Minecraft: ${args.mcVersion}`,
        `  - Java: ${args.javaVersion}`,
        `  - Node.js: ${process.version}`,
        "+ Runner:",
        `  - OS: ${process.platform}`,
        `  - Arch: ${process.arch}`,
    ]

    return wrap("details", joinLine(
        wrap("summary", "Environment Information"),
        wrap("pre", wrap("code", envInfo.join("\n")))
    ))
}

const getLicenseMessage = () => {
    return joinLine(
        wrap("h2" , "License"),
        wrap("small", `This test report has been generated by ${
            wrap("a", "Scenamatica", { href: "https://github.com/TeamKUN/Scenamatica" })
        } and licensed under ${
            wrap("a", "MIT License", { href: "https://github.com/TeamKUN/Scenamatica/blob/main/LICENSE" })
        }.`),
        "<br />",
        wrap("small", "You can redistribute it and/or modify it under the terms of the MIT License.")
    )
}

export const wrap = (tag: string, text: string, props: { [key: string]: string } = {}) => {
    const attributes = Object.entries(props).map(([key, value]) => `${key}="${value}"`).join(" ")

    return `<${tag} ${attributes}>${text}</${tag}>`
}

export const joinLine = (...texts: string[]) => {
    return texts.join("\n")
}

export const join = (delimiter: string, ...texts: string[]) => {
    return texts.join(delimiter)
}

const combine = (...texts: string[]) => {
    return texts.join("")
}
