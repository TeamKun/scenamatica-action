import {ChildProcess, spawn} from "child_process";
import {debug, fail, info} from "../utils";
import {deployPlugin} from "./deployer";
import {onDataReceived} from "./client";

const JAVA_COMMAND = "java {args} -jar {jar} nogui"

let serverProcess: ChildProcess | null = null
let attemptStop = false

export function startServer(workDir: string, executable: string, args: string[] = []) {
    if (serverProcess !== null)
        throw new Error("Server is already running")

    info(`Starting server with executable ${executable} and args ${args.join(" ")}`)

    const command = JAVA_COMMAND.replace("{args}", args.join(" ")).replace("{jar}", executable)

    const process = spawn(command, {
        cwd: workDir,
        shell: true,
        stdio: "inherit"
    });

    attachProcessDebug(process)

    return serverProcess = process
}

export function stopServer() {
    if (serverProcess === null || attemptStop)
        return

    attemptStop = true

    info("Stopping server...")

    serverProcess.stdin!.write("stop\n")

    setTimeout(() => {
        if (serverProcess !== null && !serverProcess.killed) {
            info("Server did not stop in time, killing...")
            serverProcess.kill()
        }

        serverProcess = null
        attemptStop = false
    }, 1000 * 10);
}

export async function startTests(serverDir: string, executable: string, pluginFile: string) {
    info(`Starting tests of plugin ${pluginFile}.`)

    await deployPlugin(serverDir, pluginFile)

    const process = startServer(serverDir, executable)

    attachProcessDebug(process)

    process.stdout!.on("data", onDataReceived)
}

export async function endTests(succeed: boolean) {
    info("Ending tests, shutting down server...")
    stopServer()

    if (succeed) {
        info("Tests succeeded")

        process.exit(0)

    } else {
        info("Tests failed")

        fail("Some tests failed")
    }
}

function attachProcessDebug(process: ChildProcess) {
    process.on("error", (error) => {
        info(`Server exited with error ${error}`)
        fail("Server exited with error: " + error)
    });

    process.stdout!.on("data", (data) => {
        debug(data.toString())
    });

    process.stderr!.on("data", (data) => {
        debug(data.toString())
    });
}
