import * as fs from "node:fs";
import ServerDeployer from "./server/deployer.js";
import type {Args} from "./utils.js";
import {args} from "./utils.js";
import { info, setFailed } from "@actions/core";
import { context, getOctokit } from "@actions/github";
import type { PullRequestInfo } from "./outputs/pull-request/appender";
import ServerManager from "./server/controller";

class Main {
    private readonly args: Args;

    private readonly pullRequest: { number: number } | undefined;

    private readonly githubToken: string;

    public constructor() {
        this.args = args;
        this.pullRequest = context.payload.pull_request;
        this.githubToken = this.args.githubToken;
    }

    public async run(): Promise<void> {
        const {
            mcVersion,
            javaVersion,
            scenamaticaVersion,
            serverDir,
            pluginFile,
            uploadXMLReport
        } = this.args;

        if (!fs.existsSync(pluginFile)) {
            setFailed(`Plugin file ${pluginFile} does not exist`);

            return;
        }

        const paper = await ServerDeployer.deployServer(
            serverDir,
            javaVersion,
            mcVersion,
            scenamaticaVersion,
            uploadXMLReport
        );

        info("Starting tests...");

        const controller = new ServerManager(serverDir)

        if (this.pullRequest) {
            Main.initPRMode(controller, this.pullRequest, this.githubToken);
        }

        await controller.startTests(
            paper,
            pluginFile
        )
    }

    private static initPRMode(client: ServerManager, pullRequest: { number: number }, token: string): void {
        info(`Running in Pull Request mode for PR #${pullRequest.number}`);

        const prInfo: PullRequestInfo = {
            number: pullRequest.number,
            octokit: getOctokit(token),
            owner: context.repo.owner,
            repository: context.repo.repo,
        };

        client.enablePullRequestMode(prInfo)
    }
}

const deployment = new Main();

deployment.run().catch((error) => {
    if (error instanceof Error) setFailed(error);
    else {
        const message = error as string;

        setFailed(message);
    }
});
