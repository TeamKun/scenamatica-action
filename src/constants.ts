import {urlEncode} from "./utils";

export const ENV_NO_SCENAMATICA = "NO_SCENAMATICA"

export const PARAMETER_DEFAULTS = {
    java: "17",
    serverDir: "server",
    minecraft: "1.16.5",
    scenamatica: "0.8.0",
    failThreshold: 0,
    graphicalSummary: true,
    uploadXMLReport: true
}

const REPO = {
    owner: "TeamKun",
    name: "Scenamatica",
}

const BUG_REPORT_SETTINGS = {
    assignees: ["PeyaPeyaPeyang"],
    labels: ["Type: Bug"],
    template: "bug_report.yml",
    title: "【バグ】 "
}

export const BUG_REPORT_URL = `https://github.com/${REPO.owner}/${REPO.name}/issues/new?`
    + `assignees=${urlEncode(BUG_REPORT_SETTINGS.assignees.join(","))}`
    + `&labels=${urlEncode(BUG_REPORT_SETTINGS.labels.join(","))}`
    + `&template=${urlEncode(BUG_REPORT_SETTINGS.template)}`
    + `&title=${urlEncode(BUG_REPORT_SETTINGS.title)}`
