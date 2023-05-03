import {fail, info, isNoScenamatica, warn} from "../utils.js"
import {deployPlugin} from "./deployer.js"
import {kill, onDataReceived} from "./client";
import {spawn} from "node:child_process";
import type {Writable} from "node:stream";
import type {ChildProcess} from "node:child_process";
import * as fs from "node:fs";

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

        if (line.endsWith("\n"))
            info(line.slice(0, - 1))
        else
            info(line)
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
        serverProcess?.kill("SIGKILL")
    }, 1000 * 20)
}

export const startTests = async (serverDir: string, executable: string, pluginFile: string) => {
    info(`Starting tests of plugin ${pluginFile}.`)

    if (isNoScenamatica())
        await removeScenamatica(serverDir)


    await deployPlugin(serverDir, pluginFile)

    const cp = createServerProcess(serverDir, executable)

    cp.stdout.on("data", async (data: Buffer) => {
        await onDataReceived(data.toString("utf8"))
    })
}

const removeScenamatica = async (serverDir: string) => {
    info("Removing Scenamatica from server...")

    const files = await fs.promises.readdir(serverDir)

    for (const file of files) {
        if (file.startsWith("Scenamatica") && file.endsWith(".jar")) {
            info(`Removing ${file}...`)
            await fs.promises.rm(file)
        }
    }
}

export const endTests = (succeed: boolean) => {
    info("Ending tests, shutting down server...")

    kill()
    stopServer()

    if (succeed) {
        info("Tests succeeded")

        process.exit(0)
    } else
        fail("Tests failed")
}
