import {fail, info, warn} from "../utils.js"
import {deployPlugin} from "./deployer.js"
import {exec} from "@actions/exec";
import {onDataReceived} from "./client";

let serverStdin: Buffer | undefined

const genArgs = (executable: string, args: string[]) => {
    return [
        ...args,
        "-jar",
        executable,
        "nogui"
    ]
}

export const startServerOnly = async (workDir: string, executable: string, args: string[] = []): Promise<number> => {
    info(`Starting server with executable ${executable} and args ${args.join(" ")}`)

    const stdin = Buffer.alloc(1024)

    return exec("java", genArgs(executable, args), {
        cwd: workDir,
        input: stdin,
        listeners: {
            stdline: (data: string) => {
                info(data)
                if (data.includes("Done") && data.includes("For help, type "))
                    stdin.write("stop\n")
            },
            errline: (data: string) => {
                warn(data)
            }
        }
    })
}

export const stopServer = () => {
    if (!serverStdin)
        return

    info("Stopping server...")

    serverStdin.write("stop\n")
}

export const startTests = async (serverDir: string, executable: string, pluginFile: string) => {
    info(`Starting tests of plugin ${pluginFile}.`)

    await deployPlugin(serverDir, pluginFile)

    const stdin = Buffer.alloc(1024)

    return exec("java", genArgs(executable, []), {
        cwd: serverDir,
        input: stdin,
        listeners: {
            stdline: onDataReceived
        }
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
