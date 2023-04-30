import * as fs from "fs"
import { fail } from "./utils"
import { deployServer } from "./server/deployer"
import { startTests } from "./server/controller"
import { getArguments, Args } from "./utils"

async function main(): Promise<void> {
    const args: Args = getArguments()

    const mcVersion: string = args.mcVersion
    const scenamaticaVersion: string = args.scenamaticaVersion
    const serverDir: string = args.serverDir
    const pluginFile: string = args.pluginFile
    const javaVersion: string = args.javaVersion

    if (!fs.existsSync(pluginFile)) {
        await fail(`Plugin file ${pluginFile} does not exist`)
        return
    }

    try {
        const paper = await deployServer(serverDir, javaVersion, mcVersion, scenamaticaVersion)
        await startTests(serverDir, paper, pluginFile)
    } catch (error: any) {
        fail(error)
    }
}

main().catch((error) => {
    fail(error)
})
