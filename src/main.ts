import {fail, getArguments} from "./utils";
import * as fs from "fs";
import {deployServer} from "./server/deployer";
import {startTests} from "./server/controller";

async function main(): Promise<void> {
    const args = getArguments()

    const mcVersion = args.mcVersion
    const scenamaticaVersion = args.scenamaticaVersion
    const serverDir = args.serverDir
    const pluginFile = args.pluginFile
    const javaVersion = args.javaVersion

    if (!fs.existsSync(pluginFile)) {
        await fail(`Plugin file ${pluginFile} does not exist`)
        return
    }
    await deployServer(serverDir, javaVersion, mcVersion, scenamaticaVersion)
        .then(paper => {
            startTests(serverDir, paper, pluginFile)
        })
        .catch(error => {
            fail(error)
        })
}
main().catch((error) => {
    fail(error);
});
