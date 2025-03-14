import * as fs from "node:fs";
import ServerDeployer from "./server/deployer.js";
import {args} from "./utils.js";
import {error, info, setFailed} from "@actions/core";
import { context, getOctokit } from "@actions/github";
import type { PullRequestInfo } from "./outputs/pull-request/appender";
import ServerManager from "./server/controller";

class Main {
    private readonly isPullRequestRun: { number: number } | undefined;

    private readonly githubToken: string;

    public constructor() {
        this.isPullRequestRun = context.payload.pull_request;
        this.githubToken = args.githubToken;
    }

    public async run(): Promise<void> {
        const {
            mcVersion,
            javaVersion,
            scenamaticaVersion,
            serverDir,
            pluginFile,
            uploadXMLReport,
            pullRequest
        } = args;

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

        if (this.isPullRequestRun && pullRequest) {
            if (this.githubToken) {
                Main.initPRMode(controller, this.isPullRequestRun, this.githubToken);
            } else {
                error("The Github token is required for PR mode, but it was not provided");
                info("The tests will run without PR mode");
            }
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

deployment.run().catch((error_) => {
    if (error_ instanceof Error) setFailed(error_);
    else {
        const message = error_ as string;

        setFailed(message);
    }
});
