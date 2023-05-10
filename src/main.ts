import * as fs from "node:fs"
import { deployServer } from "./server/deployer.js"
import { startTests } from "./server/controller.js"
import type { Args } from "./utils.js"
import { getArguments } from "./utils.js"
import {info, setFailed} from "@actions/core";

const main = async (): Promise<void> => {
    const args: Args = getArguments()
    const { mcVersion } = args
    const { scenamaticaVersion } = args
    const { serverDir } = args
    const { pluginFile } = args
    const { javaVersion } = args

    if (!fs.existsSync(pluginFile)) {
        setFailed(`Plugin file ${pluginFile} does not exist`)

        return
    }

    const paper = await deployServer(serverDir, javaVersion, mcVersion, scenamaticaVersion)

    info("Starting tests...")

    await startTests(serverDir, paper, pluginFile)
}

main().catch((error) => {
    if (error instanceof Error)
        setFailed(error)
    else {
        const message = error as string

        setFailed(message)
    }
})
