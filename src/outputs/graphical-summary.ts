// eslint-disable-next-line eslint-comments/disable-enable-pair
/* eslint-disable unicorn/switch-case-braces */
import type {PacketSessionEnd} from "../packets";
import {TestResultCause} from "../packets";

const MAX_PIE_RESULTS = 20

export const generateGraphicalSummary = (result: PacketSessionEnd) => {
    const ganttChart = generateGanttChart(result)
    const pieChart = generatePieChart(result)

    return `

### Graphical Summary

\`\`\`mermaid
${ganttChart}
\`\`\`

\`\`\`mermaid
${pieChart}
\`\`\`

`
}


const generateGanttChart = (result: PacketSessionEnd) => {
    const title = "Scenamatica Test Timeline"
    const dateFormat = "HH:mm:ss.SSS"
    const axisFormat = "%M:%S"

    const results = result.results
        .sort((a, b) => a.startedAt - b.startedAt)
        .map((test) => {
            const duration = test.finishedAt - test.startedAt
            const cause = causeToMermaidStatus(test.cause)
            const start = test.startedAt - result.startedAt
            const end = start + duration

            return `${test.scenario.name}: ${cause} ${toMermaidTime(start)}, ${toMermaidTime(end)}`
        })

    return `
gantt title ${title}
dateFormat ${dateFormat}
axisFormat ${axisFormat}
Session Start: milestone, 00:00:00.000, 0
${results.join("\n")}
Session End: milestone, ${toMermaidTime(result.finishedAt - result.startedAt)}, 0
`
}

const generatePieChart = (result: PacketSessionEnd) => {
    const title = "Scenamatica Test Results"
    const totalDuration = result.finishedAt - result.startedAt

    const results = result.results
        .sort((a, b) => {
            const durationA = a.finishedAt - a.startedAt
            const durationB = b.finishedAt - b.startedAt

            return durationB - durationA  // Duration で降順ソート
        })
        .slice(0, MAX_PIE_RESULTS)
        .map((test, idx) => {
            const numStr = pad(idx + 1, 2)
            const duration = test.finishedAt - test.startedAt
            const durationStr = toMermaidTime(duration)
            const ratio = duration / totalDuration

            return `"${numStr}. ${durationStr} - ${test.scenario.name}": ${ratio}`
        })

    return `
pie title ${title}
${results.join("\n")}
`
}

const causeToMermaidStatus = (cause: TestResultCause) => {
    switch (cause) {
        case TestResultCause.PASSED:
            return "active, "

        case TestResultCause.SKIPPED:
            return ""

        case TestResultCause.CANCELLED:
            return "done, "

        default:
            return "crit, "

    }
}

const toMermaidTime = (timeMillis: number) => {
    const tzOffset = new Date().getTimezoneOffset() * 60 * 1000
    const date = new Date(timeMillis - tzOffset)
    const hours = date.getHours()
    const minutes = date.getMinutes()
    const seconds = date.getSeconds()
    const milliseconds = date.getMilliseconds()


    return `${pad(hours, 2)}:${pad(minutes, 2)}:${pad(seconds, 2)}.${pad(milliseconds, 3)}`
}

const pad = (num: number, size: number) => {
    let s = `${num}`

    while (s.length < size) s = `0${s}`

    return s
}
