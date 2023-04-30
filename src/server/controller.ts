import type { ChildProcess } from "node:child_process"
import { spawn } from "node:child_process"
import { debug, fail, info } from "../utils"
import { deployPlugin } from "./deployer"
import { onDataReceived } from "./client"

const JAVA_COMMAND = "java {args} -jar {jar} nogui"

let serverProcess: ChildProcess | undefined
let attemptStop = false

export const startServer = (workDir: string, executable: string, args: string[] = []) => {
    if (serverProcess) throw new Error("Server is already running")

    info(`Starting server with executable ${executable} and args ${args.join(" ")}`)

    const command = JAVA_COMMAND.replace("{args}", args.join(" ")).replace("{jar}", executable)

    const javaProcess = spawn(command, {
        cwd: workDir,
        shell: true,
        stdio: "inherit",
    })

    attachProcessDebug(javaProcess)

    serverProcess = javaProcess

    return javaProcess
}

export const stopServer = () => {
    if (serverProcess === undefined || attemptStop) return

    attemptStop = true

    info("Stopping server...")

    serverProcess.stdin!.write("stop\n")

    setTimeout(() => {
        if (serverProcess !== undefined && !serverProcess.killed) {
            info("Server did not stop in time, killing...")
            serverProcess.kill()
        }

        serverProcess = undefined
        attemptStop = false
    }, 1000 * 10)
}

export const startTests = async (serverDir: string, executable: string, pluginFile: string) => {
    info(`Starting tests of plugin ${pluginFile}.`)

    await deployPlugin(serverDir, pluginFile)

    const javaProcess = startServer(serverDir, executable)

    attachProcessDebug(javaProcess)

    javaProcess.stdout!.on("data", onDataReceived)
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

const attachProcessDebug = (childProcess: ChildProcess) => {
    childProcess.on("error", (error: Error) => {
        const errorMessage = error.message

        info(`Server exited with error ${errorMessage}`)
        fail(error)
    })

    childProcess.stdout!.on("data", (data) => {
        const dataString = (data as Buffer).toString()

        debug(dataString)
    })

    childProcess.stderr!.on("data", (data) => {
        const dataString = (data as Buffer).toString()

        debug(dataString)
    })
}
