import {getArguments, isNoScenamatica} from "../utils.js";
import ServerDeployer from "./deployer.js";
import type {ChildProcess} from "node:child_process";
import {spawn} from "node:child_process";
import type {Writable} from "node:stream";
import * as fs from "node:fs";
import path from "node:path";
import {info, setFailed, warning} from "@actions/core";
import ScenamaticaPacketProcessor from "./client";
import type {PullRequestInfo} from "../outputs/pull-request/appender";
import OutputPublisher from "../outputs/publisher";

class ServerManager {
    private readonly serverDirectory: string

    private readonly publisher: OutputPublisher;

    private readonly client: ScenamaticaPacketProcessor;

    private serverProcess: ChildProcess | undefined;

    private serverStdin: Writable | undefined;

    public constructor(serverDirectory: string) {
        this.serverDirectory = serverDirectory
        this.publisher = new OutputPublisher()
        this.client = new ScenamaticaPacketProcessor(this.publisher, this.endTests.bind(this))
    }

    public getScenamaticaDirectory(): string {
        return path.join(this.serverDirectory, "plugins", "Scenamatica")
    }

    private genArgs(executable: string, args: string[]): string[] {
        return [
            ...args,
            "-jar",
            executable,
            "nogui"
        ];
    }

    private createServerProcess(executable: string, args: string[] = []): ChildProcess {
        const cp = spawn(
            "java",
            this.genArgs(executable, args),
            {
                cwd: this.serverDirectory
            }
        );

        this.serverStdin = cp.stdin;
        this.serverProcess = cp;

        return cp;
    }

    public async startServerOnly(executable: string, args: string[] = []): Promise<number> {
        info(`Starting server with executable ${executable} and args ${args.join(" ")}`);

        const cp = this.createServerProcess(executable, args);

        cp.stdout!.on("data", (data: Buffer) => {
            const line = data.toString("utf8");

            if (line.includes("Done") && line.includes("For help, type \"help\""))
                this.serverStdin?.write("stop\n");

            if (line.endsWith("\n"))
                info(line.slice(0, -1));
            else
                info(line);
        });

        return new Promise<number>((resolve, reject) => {
            cp.on("exit", (code) => {
                if (code === 0)
                    resolve(code);
                else
                    reject(code);
            });
        });
    }

    public stopServer(): void {
        if (!this.serverStdin || !this.serverProcess)
            return;

        info("Stopping server...");

        this.serverStdin.write("stop\n");

        setTimeout(() => {
            if (this.serverProcess!.killed)
                return;

            warning("Server didn't stop in time, killing it...");
            this.serverProcess?.kill("SIGKILL");
        }, 1000 * 20);
    }

    private async removeScenamatica(): Promise<void> {
        info("Removing Scenamatica from server...");

        const pluginDir = path.join(this.serverDirectory, "plugins");
        const files = await fs.promises.readdir(pluginDir);

        for (const file of files) {
            if (file.includes("Scenamatica") && file.endsWith(".jar")) {
                info(`Removing ${file}...`);
                await fs.promises.rm(path.join(pluginDir, file));
            }
        }
    }

    public async startTests(executable: string, pluginFile: string): Promise<void> {
        info(`Starting tests of plugin ${pluginFile}.`);

        if (isNoScenamatica())
            await this.removeScenamatica();

        await ServerDeployer.deployPlugin(this.serverDirectory, pluginFile);

        const cp = this.createServerProcess(executable);

        cp.stdout!.on("data", async (data: Buffer) => {
            await this.client.onDataReceived(data.toString("utf8"))
        })
    }

    public async endTests(succeed: boolean): Promise<void> {
        info("Ending tests, shutting down server...");

        if (getArguments().uploadXMLReport) {
            info("Waiting for the server for 5 seconds to save the reports.")
            await new Promise<void>(resolve => {
                setTimeout(async () => {
                    await this.publisher.publishXMLReports(this.findReportPaths())
                    resolve()
                }, 5000)
            })
        }

        this.stopServer();

        await this.publisher.summaryPrinter.printFooter();

        let code: number;

        if (succeed) {
            info("Tests succeeded");
            code = 0;
        } else {
            setFailed("Tests failed");
            code = 1;
        }

        process.exit(code);
    }

    public findReportPaths(): string[] {
        const baseDir = this.getScenamaticaDirectory();
        const reportsDir = path.join(baseDir, 'reports');

        if (!fs.existsSync(reportsDir)) {
            warning(`Reports directory not found at ${reportsDir}`);

            return []
        }

        const files = fs.readdirSync(reportsDir);
        const xmlFiles = files.filter(file => path.extname(file).toLowerCase() === '.xml');

        if (xmlFiles.length === 0) {
            warning(`No XML report files found in ${reportsDir}`);

            return []
        }

        // フルパスに変換して返す
        return xmlFiles.map(file => path.join(reportsDir, file))
    }

    public  getDirectoryContents(directoryPath: string): void {
        const items = fs.readdirSync(directoryPath);

        for (const item of items) {
            // アイテムのパスを取得
            const itemPath = path.join(directoryPath, item);
            const isFile = fs.statSync(itemPath).isFile();

            if (isFile) {
                console.log(itemPath)
            } else {
                this.getDirectoryContents(itemPath)
            }
        }
    }

    public enablePullRequestMode(pullRequest: PullRequestInfo): void {
        this.client.enablePullRequestMode(pullRequest)
    }
}

export default ServerManager
