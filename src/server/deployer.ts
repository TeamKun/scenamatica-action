import * as tc from "@actions/tool-cache"
import * as io from "@actions/io"
import {fail, info} from "../utils"
import {startServer} from "./controller"
import path from "path"
import * as fs from "fs";
import * as yaml from "js-yaml"

const PAPER_VERSION_URL = "https://papermc.io/api/v2/projects/paper/versions/{version}/"
const PAPER_DOWNLOAD_URL = `${PAPER_VERSION_URL}/builds/{build}/downloads/paper-{version}-{build}.jar`

const SCENAMATICA_URL = "https://github.com/TeamKun/Scenamatica/releases/download/v{version}/Scenamatica-{version}.jar"

async function restoreCache(dir: string, mcVersion: string, scenamaticaVersion: string): Promise<boolean>
{
    const cacheDirectory = tc.find("runner", `${mcVersion}-scenamatica-v${scenamaticaVersion}`)

    if (cacheDirectory)
    {
        info(`Restoring server cache from ${cacheDirectory}`)
        await io.cp(cacheDirectory, dir, {recursive: true})
        return true
    }

    return false
}

async function retrieveLatestPaperBuildFor(mcVersion: string)
{
    const url = PAPER_VERSION_URL.replace("{version}", mcVersion)
    const response = await fetch(url)
    const json = await response.json()
    return json.versions[0]
}

async function downloadLatestPaper(destDir: string, mcVersion: string)
{
    info(`Retrieving latest Paper build for ${mcVersion}`)
    const build = await retrieveLatestPaperBuildFor(mcVersion)
    info(`Retrieved latest Paper build for ${mcVersion}: The latest build is ${build}`)

    const url = PAPER_DOWNLOAD_URL.replace("{version}", mcVersion).replace("{build}", build)
    info(`Downloading Paper ${mcVersion} build ${build} from ${url}`)

    await io.mkdirP(destDir)
    const dest = await tc.downloadTool(url, path.join(destDir, "paper.jar"))
    info(`Downloaded Paper ${mcVersion} build ${build} to ${dest}`)

    return {
        build: build,
        paperPath: dest
    }
}

async function writeEula(dir: string)
{
    const eulaPath = path.join(dir, "eula.txt")
    const eulaContent = "eula=true\n"

    await io.rmRF(eulaPath)  // 以前の eula.txt を削除
    await fs.promises.writeFile(eulaPath, eulaContent)
    info(`Wrote eula.txt to ${eulaPath}`)
}

async function downloadScenamatica(destDir: string, version: string)
{
    const url = SCENAMATICA_URL.replace("{version}", version)
    info(`Downloading Scenamatica ${version} from ${url}`)

    const destPath = await tc.downloadTool(url, path.join(destDir, `Scenamatica-${version}.jar`))
    info(`Downloaded Scenamatica ${version} to ${destPath}`)

    return destPath
}

export async function deployServer(dir: string, mcVersion: string, scenamaticaVersion: string): Promise<string>
{
    // キャッシュの復元
    const cached = await restoreCache(dir, mcVersion, scenamaticaVersion)

    if (cached)
        return new Promise<string>((resolve) => {
            resolve(path.join(dir, "paper.jar"))
        })
    // キャッシュがないので Paper をビルドする。

    info("Building server...")
    // Paper のダウンロード
    const {build, paperPath} = await downloadLatestPaper(dir, mcVersion)

    // Paper にビルドさせる(初回実行）
    return new Promise<string>((resolve, reject) => {
        startServer(dir, paperPath).on("exit", (code) => {
            if (code === 0)
            {
                initServer(dir, mcVersion, build, scenamaticaVersion)
                resolve(paperPath)
            }
            else
            {
                fail("Server exited with error code " + code)
                reject(code)
            }
        })
    });
}

export async function deployPlugin(serverDir: string, pluginFile: string)
{
    const pluginDir = path.join(serverDir, "plugins")
    await io.mkdirP(pluginDir)

    await io.cp(pluginFile, pluginDir)
}

async function initServer(dir: string, mcVersion: string, paperBuild: string, scenamaticaVersion: string)
{
    const pluginDir = path.join(dir, "plugins")
    await io.mkdirP(pluginDir)

    await writeEula(dir)  // eula.txt を書き込まないと Paper が起動Vしない
    await downloadScenamatica(pluginDir, scenamaticaVersion)

    await initScenamaticaConfig(path.join(pluginDir, "Scenamatica"))

    await tc.cacheDir(dir, "paperclip", `${mcVersion}+${paperBuild}-scenamatica-v${scenamaticaVersion}`)
}

async function initScenamaticaConfig(configDir: string)
{
    const configPath = path.join(configDir, "configDir.yml")
    const configData = yaml.load(await fs.promises.readFile(configPath, "utf-8")) as any

    configData["interfaces"]["raw"] = true

    await fs.promises.writeFile(configPath, yaml.dump(configData))
}
