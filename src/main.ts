import * as fs from "node:fs"
import { deployServer } from "./server/deployer.js"
import { startTests } from "./server/controller.js"
import type { Args } from "./utils.js"
import { getArguments } from "./utils.js"
import {info, setFailed} from "@actions/core";
import {context, getOctokit} from "@actions/github";
import type {PullRequestInfo} from "./outputs/pull-request/appender";
import {initPullRequest} from "./server/client";

const main = async (): Promise<void> => {
    const args: Args = getArguments()

    const { mcVersion,
        javaVersion,
        scenamaticaVersion,
        serverDir,
        pluginFile,
        githubToken
    } = args

    const pullRequest = context.payload.pull_request

    if (pullRequest) {
        initPRMode(pullRequest, githubToken)
    }

    if (!fs.existsSync(pluginFile)) {
        setFailed(`Plugin file ${pluginFile} does not exist`)

        return
    }

    const paper = await deployServer(serverDir, javaVersion, mcVersion, scenamaticaVersion)

    info("Starting tests...")

    await startTests(serverDir, paper, pluginFile)
}

const initPRMode = (pullRequest: {number: number}, token: string) => {
    info(`Running in Pull Request mode for PR #${pullRequest.number}`)

    const prInfo: PullRequestInfo = {
        number: pullRequest.number,
        octokit: getOctokit(token),
        owner: context.repo.owner,
        repository: context.repo.repo
    }


    initPullRequest(prInfo)
}

main().catch((error) => {
    if (error instanceof Error)
        setFailed(error)
    else {
        const message = error as string

        setFailed(message)
    }
})
