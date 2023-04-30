import * as fs from "node:fs"
import { fail } from "./utils"
import { deployServer } from "./server/deployer"
import { startTests } from "./server/controller"
import type { Args } from "./utils"
import { getArguments } from "./utils"

const main = async (): Promise<void> => {
    const args: Args = getArguments()
    const { mcVersion } = args
    const { scenamaticaVersion } = args
    const { serverDir } = args
    const { pluginFile } = args
    const { javaVersion } = args

    if (!fs.existsSync(pluginFile)) {
        fail(`Plugin file ${pluginFile} does not exist`)

        return
    }

    const paper = await deployServer(serverDir, javaVersion, mcVersion, scenamaticaVersion)

    await startTests(serverDir, paper, pluginFile)
}

main().catch((error) => {
    if (error instanceof Error) fail(error)
    else {
        const message = error as string

        fail(message)
    }
})
