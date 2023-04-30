import * as tc from "@actions/tool-cache"
import * as io from "@actions/io"
import * as core from "@actions/core"
import path from "node:path"
import * as fs from "node:fs"
import * as yaml from "js-yaml"
import { exec } from "@actions/exec"
import {fail, info} from "../utils.js";
import {startServer} from "./controller.js";
import fetch from "node-fetch"

const PAPER_VERSION_URL = "https://papermc.io/api/v2/projects/paper/versions/{version}/"
const PAPER_DOWNLOAD_URL = `${PAPER_VERSION_URL}/builds/{build}/downloads/paper-{version}-{build}.jar`
const SCENAMATICA_URL = "https://github.com/TeamKun/Scenamatica/releases/download/v{version}/Scenamatica-{version}.jar"

const JAVA_FETCH_URL =
    "https://api.azul.com/zulu/download/community/v1.0/bundles/?os={os}&arch={arch}&ext={ext}&java_version={version}&type=jdk"

const genCacheVersion = (javaVersion: string, mcVersion: string, scenamaticaVersion: string) => {
    return `${mcVersion}-scenamatica-v${scenamaticaVersion}@java-${javaVersion}`
}

const restoreCache = async (
    dir: string,
    javaVersion: string,
    mcVersion: string,
    scenamaticaVersion: string,
): Promise<boolean> => {
    const cacheDirectory = tc.find("scenamatica", genCacheVersion(javaVersion, mcVersion, scenamaticaVersion))

    if (cacheDirectory) {
        info(`Restoring server cache from ${cacheDirectory}`)
        await io.cp(cacheDirectory, dir, { recursive: true })

        return true
    }

    return false
}

const retrieveLatestPaperBuildFor = async (mcVersion: string): Promise<string> => {
    const url = PAPER_VERSION_URL.replace(/\{version}/g, mcVersion)
    const response = await fetch(url)
    const json = (await response.json()) as { builds: string[] }

    return json.builds[0] // 最新のビルド番号を返す
}

const downloadLatestPaper = async (destDir: string, mcVersion: string) => {
    info(`Retrieving latest Paper build for ${mcVersion}`)

    const build = await retrieveLatestPaperBuildFor(mcVersion)

    info(`Retrieved latest Paper build for ${mcVersion}: The latest build is ${build}`)

    const url = PAPER_DOWNLOAD_URL
        .replace(/\{version}/g, mcVersion)
        .replace(/\{build}/g, build)

    info(`Downloading Paper ${mcVersion} build ${build} from ${url}`)

    await io.mkdirP(destDir)

    const dest = await tc.downloadTool(url, path.join(destDir, "paper.jar"))

    info(`Downloaded Paper ${mcVersion} build ${build} to ${dest}`)

    return {
        build,
        paperPath: dest,
    }
}

const writeEula = async (dir: string) => {
    const eulaPath = path.join(dir, "eula.txt")
    const eulaContent = "eula=true\n"

    await io.rmRF(eulaPath) // 以前の eula.txt を削除
    await fs.promises.writeFile(eulaPath, eulaContent)
    info(`Wrote eula.txt to ${eulaPath}`)
}

const downloadScenamatica = async (destDir: string, version: string) => {
    const url = SCENAMATICA_URL.replace(/\{version}/g, version)

    info(`Downloading Scenamatica ${version} from ${url}`)

    const destPath = await tc.downloadTool(url, path.join(destDir, `Scenamatica-${version}.jar`))

    info(`Downloaded Scenamatica ${version} to ${destPath}`)

    return destPath
}

const fetchLatestJavaLinkFor = async (version: string) => {
    const processPlatform = process.platform
    const platform = processPlatform === "win32" ? "windows" : processPlatform === "darwin" ? "macos" : "linux"
    const arch = process.arch === "x64" ? "x86_64" : "x86"
    const ext = platform === "windows" ? "zip" : "tar.gz"

    const url = JAVA_FETCH_URL.replace(/\{os}/g, platform)
        .replace(/\{arch}/g, arch)
        .replace(/\{ext}/g, ext)
        .replace(/\{version}/g, version)

    const response = await fetch(url)
    const json = (await response.json()) as Array<{ url: string }>

    return {
        url: json[0].url,
        isTar: ext === "tar.gz",
    }
}

const downloadJava = async (destBaseDir: string, version: string) => {
    info(`Retrieving latest Java build for ${version}`)

    const { url, isTar } = await fetchLatestJavaLinkFor(version) // 最新の Java ビルドの URL を取得

    info(`Retrieved latest Java build for ${version}: ${url}`)

    const dest = await tc.downloadTool(url, path.join(destBaseDir, "java-package"))

    info(`Downloaded Java ${version} to ${dest}`)

    const destDir = path.join(destBaseDir, "java")

    info("Extracting...")
    await (isTar ? tc.extractTar(dest, destDir) : tc.extractZip(dest, destDir))

    core.addPath(path.join(destDir, "bin"))

    info(`Installed Java ${version}`)
}

const isJavaInstalled = async () => {
    try {
        await exec("java", ["-version"])

        return true
    } catch {
        return false
    }
}

export const deployServer = async (
    dir: string,
    javaVersion: string,
    mcVersion: string,
    scenamaticaVersion: string,
): Promise<string> => {
    // キャッシュの復元
    const cached = await restoreCache(dir, javaVersion, mcVersion, scenamaticaVersion)

    if (cached)
        return new Promise<string>((resolve) => {
            resolve(path.join(dir, "paper.jar"))
        })
    // キャッシュがないので Paper をビルドする。

    info("Building server...")

    // Java のダウンロード
    if (!(await isJavaInstalled())) await downloadJava(dir, javaVersion)

    // Paper のダウンロード
    const { build, paperPath } = await downloadLatestPaper(dir, mcVersion)

    // Paper にビルドさせる(初回実行）
    return new Promise<string>((resolve, reject) => {
        startServer(dir, paperPath).on("exit", async (code: number) => {
            if (code === 0) {
                await initServer(dir, javaVersion, mcVersion, build, scenamaticaVersion)
                resolve(paperPath)
            } else {
                fail(`Server exited with error code ${code}`)
                reject(code)
            }
        })
    })
}

export const deployPlugin = async (serverDir: string, pluginFile: string) => {
    const pluginDir = path.join(serverDir, "plugins")

    await io.mkdirP(pluginDir)

    await io.cp(pluginFile, pluginDir)
}

const initServer = async (
    dir: string,
    javaVersion: string,
    mcVersion: string,
    paperBuild: string,
    scenamaticaVersion: string,
) => {
    const pluginDir = path.join(dir, "plugins")

    await io.mkdirP(pluginDir)

    await writeEula(dir) // eula.txt を書き込まないと Paper が起動Vしない
    await downloadScenamatica(pluginDir, scenamaticaVersion)

    await initScenamaticaConfig(path.join(pluginDir, "Scenamatica"))

    await tc.cacheDir(dir, "scenamatica", genCacheVersion(javaVersion, mcVersion, scenamaticaVersion))
}

const initScenamaticaConfig = async (configDir: string) => {
    const configPath = path.join(configDir, "configDir.yml")

    const configData = yaml.load(await fs.promises.readFile(configPath, "utf8")) as {
        interfaces: {
            raw: boolean
        }
    }

    configData["interfaces"]["raw"] = true

    await fs.promises.writeFile(configPath, yaml.dump(configData))
}
