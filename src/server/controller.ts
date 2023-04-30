import {fail, info, warn} from "../utils.js"
import {deployPlugin} from "./deployer.js"
import {onDataReceived} from "./client";
import {spawn} from "node:child_process";
import type {Writable} from "node:stream";
import type {ChildProcess} from "node:child_process";

let serverProcess: ChildProcess | undefined
let serverStdin: Writable | undefined

const genArgs = (executable: string, args: string[]) => {
    return [
        ...args,
        "-jar",
        executable,
        "nogui"
    ]
}

const createServerProcess = (workDir: string, executable: string, args: string[] = []) => {
    const cp = spawn(
        "java",
        genArgs(executable, args),
        {
            cwd: workDir
        }
    )

    serverStdin = cp.stdin
    serverProcess = cp

    return cp
}

export const startServerOnly = async (workDir: string, executable: string, args: string[] = []) => {
    info(`Starting server with executable ${executable} and args ${args.join(" ")}`)

    const cp = createServerProcess(workDir, executable, args)

    cp.stdout.on("data", (data: Buffer) => {
        const line = data.toString("utf8")

        if (line.includes("Done") && line.includes("For help, type \"help\""))
            serverStdin?.write("stop\n")

    })

    return new Promise<number>((resolve, reject) => {
        cp.on("exit", (code) => {
            if (code === 0)
                resolve(code)
            else
                reject(code)
        })
    })
}

export const stopServer = () => {
    if (!serverStdin || !serverProcess)
        return

    info("Stopping server...")

    serverStdin.write("stop\n")
    
    setTimeout(() => {
        if (serverProcess!.killed)
            return

        warn("Server didn't stop in time, killing it...")
        serverProcess?.kill()
    }, 5000)
}

export const startTests = async (serverDir: string, executable: string, pluginFile: string) => {
    info(`Starting tests of plugin ${pluginFile}.`)

    await deployPlugin(serverDir, pluginFile)

    const cp = createServerProcess(serverDir, executable)

    cp.stdout.on("data", async (data: Buffer) => {
        await onDataReceived(data.toString("utf8"))
    })
}

export const endTests = (succeed: boolean) => {
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
