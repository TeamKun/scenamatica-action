import * as tc from "@actions/tool-cache";
import * as cache from "@actions/cache";
import * as io from "@actions/io";
import path from "node:path";
import * as fs from "node:fs";
import * as yaml from "js-yaml";
import { exec } from "@actions/exec";
import fetch from "node-fetch";
import { info} from "@actions/core";
import { compare } from "compare-versions";
import ServerManager from "./controller";
import {getArguments} from "../utils";

class ServerDeployer {
    private static readonly PAPER_NAME = "paper.jar";

    private static readonly PAPER_VERSION_URL = "https://api.papermc.io/v2/projects/paper/versions/{version}/";

    private static readonly PAPER_DOWNLOAD_URL = `${ServerDeployer.PAPER_VERSION_URL}/builds/{build}/downloads/paper-{version}-{build}.jar`;

    private static readonly SCENAMATICA_URL = "https://github.com/TeamKun/Scenamatica/releases/download/v{version}/Scenamatica-{version}.jar";

    private static readonly JAVA_FETCH_URL = "https://api.azul.com/zulu/download/community/v1.0/bundles/?os={os}&arch={arch}&ext={ext}&java_version={version}&type=jdk";

    public  getDirectoryContents(directoryPath: string): void {
        const items = fs.readdirSync(directoryPath);

        for (const item of items) {
            // アイテムのパスを取得
            const itemPath = path.join(directoryPath, item);
            const isFile = fs.statSync(itemPath).isFile();

            if (isFile) {
                console.log(itemPath)
            } else {
                this.getDirectoryContents(itemPath)
            }
        }
    }


    private static genCacheKey(javaVersion: string, mcVersion: string, scenamaticaVersion: string): string {
        return `server-${mcVersion}-scenamatica-v${scenamaticaVersion}@java-${javaVersion}`;
    }

    private static async restoreCache(dir: string, javaVersion: string, mcVersion: string, scenamaticaVersion: string): Promise<boolean> {
        const cacheKey = ServerDeployer.genCacheKey(javaVersion, mcVersion, scenamaticaVersion);

        info(`Checking cache for ${cacheKey}`);

        const cachedKey = await cache.restoreCache([dir], cacheKey);

        return cachedKey === cacheKey;
    }

    private static async retrieveLatestPaperBuildFor(mcVersion: string): Promise<string> {
        const url = ServerDeployer.PAPER_VERSION_URL.replace(/\{version}/g, mcVersion);
        const response = await fetch(url);
        const json = (await response.json()) as { builds: string[] };

        return json.builds[json.builds.length - 1]; // 最新のビルドを返す
    }

    private static async downloadLatestPaper(destDir: string, mcVersion: string): Promise<string> {
        info(`Retrieving latest Paper build for ${mcVersion}`);

        const build = await ServerDeployer.retrieveLatestPaperBuildFor(mcVersion);

        info(`Retrieved latest Paper build for ${mcVersion}: The latest build is ${build}`);

        const url = ServerDeployer.PAPER_DOWNLOAD_URL
            .replace(/\{version}/g, mcVersion)
            .replace(/\{build}/g, build);

        info(`Downloading Paper ${mcVersion} build ${build} from ${url}`);

        await io.mkdirP(destDir);

        const dest = await tc.downloadTool(url, path.join(destDir, "paper.jar"));
        // permission がないと起動できないので、chmod で付与する
        const os = process.platform === "win32" ? "windows" : "unix";

        await (os === "unix" ? exec("chmod", ["+x", dest]) : exec("icacls", [dest, "/grant", "Everyone:(F)"]));

        info(`Downloaded Paper ${mcVersion} build ${build} to ${dest}`);

        return build;
    }

    private static async writeEula(dir: string): Promise<void> {
        const eulaPath = path.join(dir, "eula.txt");
        const eulaContent = "eula=true\n";

        await fs.promises.writeFile(eulaPath, eulaContent);
        info(`Wrote eula.txt to ${eulaPath}`);
    }

    private static async downloadScenamatica(destDir: string, version: string): Promise<string> {
        let normalizedVersion = version;

        if (normalizedVersion.startsWith("v"))
            normalizedVersion = normalizedVersion.slice(1);

        const url = ServerDeployer.SCENAMATICA_URL.replace(/\{version}/g, normalizedVersion);

        info(`Downloading Scenamatica ${normalizedVersion} from ${url}`);

        const destPath = await tc.downloadTool(url, path.join(destDir, `Scenamatica-${normalizedVersion}.jar`));

        info(`Downloaded Scenamatica ${normalizedVersion} to ${destPath}`);

        return destPath;
    }

    private static async fetchLatestJavaLinkFor(version: string): Promise<{ url: string; isTar: boolean }> {
        const processPlatform = process.platform;
        const platform = processPlatform === "win32" ? "windows" : processPlatform === "darwin" ? "macos" : "linux";
        const arch = process.arch === "x64" ? "x86_64" : "x86";
        const ext = platform === "windows" ? "zip" : "tar.gz";

        const url = ServerDeployer.JAVA_FETCH_URL.replace(/\{os}/g, platform)
            .replace(/\{arch}/g, arch)
            .replace(/\{ext}/g, ext)
            .replace(/\{version}/g, version);

        const response = await fetch(url);
        const json = (await response.json()) as Array<{ url: string }>;

        return {
            url: json[0].url,
            isTar: ext === "tar.gz",
        };
    }

    private static async installJava(destBaseDir: string, version: string): Promise<void> {
        info(`Retrieving latest Java build for ${version}`);

        const { url, isTar } = await ServerDeployer.fetchLatestJavaLinkFor(version); // 最新の Java ビルドの URL を取得

        info(`Retrieved latest Java build for ${version}: ${url}`);

        const dest = await tc.downloadTool(url, path.join(destBaseDir, "java-package"));

        info(`Downloaded Java ${version} to ${dest}`);

        const destDir = path.join(destBaseDir, "java-extracted");

        info("Extracting...");
        await (isTar ? tc.extractTar(dest, destDir) : tc.extractZip(dest, destDir));

        // destBaseDir/java/わからない名前/ になるので、その中身を destBaseDir/java/ に移動する
        const items = fs.readdirSync(destDir);

        let srcDir;

        for (const item of items) {
            if (item.startsWith("zulu") && item.endsWith("linux_x64")) {
                srcDir = path.join(destDir, item);

                break;
            }
        }

        if (srcDir) {
            info(`Moving ${srcDir} to java...`);
            fs.renameSync(srcDir, path.join(destBaseDir, "java"));
        } else {
            throw new Error("Could not find the extracted Java directory.");
        }

        info(`Installed Java ${version}`);
    }

    public static async deployServer(dir: string, javaVersion: string, mcVersion: string, scenamaticaVersion: string,
                                     uploadXMLReport: boolean): Promise<string> {
        const pluginDir = path.join(dir, "plugins");
        // キャッシュの復元
        const cached = await ServerDeployer.restoreCache(dir, javaVersion, mcVersion, scenamaticaVersion);

        if (cached)
            return new Promise<string>((resolve) => {
                resolve(ServerDeployer.PAPER_NAME);
            });
        // キャッシュがないので Paper をビルドする。

        info("Building server...");

        // Java のダウンロード&インストール
        await ServerDeployer.installJava(dir, javaVersion);

        // Paper のダウンロード
        await io.mkdirP(pluginDir);
        await ServerDeployer.downloadLatestPaper(dir, mcVersion);
        await ServerDeployer.downloadScenamatica(pluginDir, scenamaticaVersion);

        await ServerDeployer.writeEula(dir); // eula.txt を書き込まないと Paper が起動しない

        const controller = new ServerManager(dir)
        const extraJavaArguments = getArguments().javaArguments

        await controller.startServerOnly(
            ServerDeployer.PAPER_NAME,
            extraJavaArguments
        )

        await ServerDeployer.initScenamaticaConfig(
            controller.getScenamaticaDirectory(),
            scenamaticaVersion,
            uploadXMLReport
        );

        await cache.saveCache([dir], ServerDeployer.genCacheKey(javaVersion, mcVersion, scenamaticaVersion));

        return ServerDeployer.PAPER_NAME;
    }

    public static async deployPlugin(serverDir: string, pluginFile: string): Promise<void> {
        const pluginDir = path.join(serverDir, "plugins");

        await io.mkdirP(pluginDir);
        await io.cp(pluginFile, pluginDir);
    }

    private static async initScenamaticaConfig(configDir: string, scenamaticaVersion: string, uploadXMLReport: boolean): Promise<void> {
        const configPath = path.join(configDir, "config.yml");

        const configData = yaml.load(await fs.promises.readFile(configPath, "utf8")) as {
            interfaces?: {
                raw: boolean;
            };
            reporting?: {
                raw: boolean;
                junit: {
                    enabled: boolean;
                };
            };
        };

        if (compare(scenamaticaVersion, "0.7.0", ">=")) {
            configData["reporting"]!["raw"] = true;
        } else {
            configData["interfaces"]!["raw"] = true;
        }

        if (uploadXMLReport) {
            configData["reporting"]!["junit"]["enabled"] = true;
        }

        await fs.promises.writeFile(configPath, yaml.dump(configData));
    }
}

export default ServerDeployer;
