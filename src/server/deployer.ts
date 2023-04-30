import * as tc from "@actions/tool-cache"
import * as cache from "@actions/cache"
import * as io from "@actions/io"
import * as core from "@actions/core"
import path from "node:path"
import * as fs from "node:fs"
import * as yaml from "js-yaml"
import { exec } from "@actions/exec"
import { info} from "../utils.js";
import fetch from "node-fetch"
import {startServerOnly} from "./controller";

const PAPER_NAME = "paper.jar"
const PAPER_VERSION_URL = "https://papermc.io/api/v2/projects/paper/versions/{version}/"
const PAPER_DOWNLOAD_URL = `${PAPER_VERSION_URL}/builds/{build}/downloads/paper-{version}-{build}.jar`
const SCENAMATICA_URL = "https://github.com/TeamKun/Scenamatica/releases/download/v{version}/Scenamatica-{version}.jar"


const JAVA_FETCH_URL =
    "https://api.azul.com/zulu/download/community/v1.0/bundles/?os={os}&arch={arch}&ext={ext}&java_version={version}&type=jdk"

const genCacheKey = (javaVersion: string, mcVersion: string, scenamaticaVersion: string) => {
    return `server-${mcVersion}-scenamatica-v${scenamaticaVersion}@java-${javaVersion}`
}

const restoreCache = async (
    dir: string,
    javaVersion: string,
    mcVersion: string,
    scenamaticaVersion: string,
) => {
    const cacheKey = genCacheKey(javaVersion, mcVersion, scenamaticaVersion)

    info(`Checking cache for ${cacheKey}`)

    const cachedKey = await cache.restoreCache([dir], cacheKey)

    return cachedKey === cacheKey
}

const retrieveLatestPaperBuildFor = async (mcVersion: string): Promise<string> => {
    const url = PAPER_VERSION_URL.replace(/\{version}/g, mcVersion)
    const response = await fetch(url)
    const json = (await response.json()) as { builds: string[] }

    return json.builds[json.builds.length - 1] // 最新のビルドを返す
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
    // permission がないと起動できないので、chmod で付与する
    const os = process.platform === "win32" ? "windows" : "unix"

    await (os === "unix" ? exec("chmod", ["+x", dest]) : exec("icacls", [dest, "/grant", "Everyone:(F)"]));

    info(`Downloaded Paper ${mcVersion} build ${build} to ${dest}`)

    return build
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
            resolve(PAPER_NAME)
        })
    // キャッシュがないので Paper をビルドする。

    info("Building server...")

    // Java のダウンロード
    if (!(await isJavaInstalled())) await downloadJava(dir, javaVersion)

    // Paper のダウンロード
    const build = await downloadLatestPaper(dir, mcVersion)

    await startServerOnly(dir, PAPER_NAME)
        .then(async () => {
            await initServer(dir, javaVersion, mcVersion, build, scenamaticaVersion)
        })
        .catch((error) => {
            throw error  // リスロー
        })

    return PAPER_NAME
}

export const deployPlugin = async (serverDir: string, pluginFile: string) => {
    const pluginDir = path.join(serverDir, "plugins")

    await io.mkdirP(pluginDir)

    await io.cp(pluginFile, pluginDir)
}

const initServer = async (
    serverDir: string,
    javaVersion: string,
    mcVersion: string,
    paperBuild: string,
    scenamaticaVersion: string,
) => {
    const pluginDir = path.join(serverDir, "plugins")

    await io.mkdirP(pluginDir)

    await writeEula(serverDir) // eula.txt を書き込まないと Paper が起動Vしない

    // Scenamatica をインスコする
    await downloadScenamatica(pluginDir, scenamaticaVersion)
    await startServerOnly(serverDir, PAPER_NAME)  // Scenaamtica の config を生成する
    await initScenamaticaConfig(path.join(pluginDir, "Scenamatica"))

    await cache.saveCache([serverDir], genCacheKey(javaVersion, mcVersion, scenamaticaVersion))
}

const initScenamaticaConfig = async (configDir: string) => {
    const configPath = path.join(configDir, "config.yml")

    const configData = yaml.load(await fs.promises.readFile(configPath, "utf8")) as {
        interfaces: {
            raw: boolean
        }
    }

    configData["interfaces"]["raw"] = true

    await fs.promises.writeFile(configPath, yaml.dump(configData))
}
