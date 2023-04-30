export class Packet<T extends Packet<T>> {
    constructor(public genre: string, public type: string, public date: number) {}
}

export interface Scenario {
    name: string
    description: string
}

export class PacketTestStart implements Packet<PacketTestStart> {
    public genre: string = "test"
    public type: string = "start"

    constructor(public date: number, public scenario: Scenario) {}
}

export enum TestState
{
    STAND_BY,
    CONTEXT_PREPARING,
    STARTING,
    RUNNING_BEFORE,
    RUNNING_MAIN,
    RUNNING_AFTER,
    FINISHED,

}

export enum TestResultCause {
    PASSED,

    CONTEXT_PREPARATION_FAILED,
    ACTION_EXECUTION_FAILED,
    ACTION_EXPECTATION_JUMPED,
    SCENARIO_TIMED_OUT,
    ILLEGAL_CONDITION,

    INTERNAL_ERROR,
    CANCELLED,
    SKIPPED
}


export class PacketTestEnd implements Packet<PacketTestEnd> {
    public genre: string = "test"
    public type: string = "end"

    constructor(public date: number, public scenario: Scenario, public state: TestState, public cause: TestResultCause, public startedAt: number, public finishedAt: number) {}
}

export class PacketSessionStart implements Packet<PacketSessionStart> {
    public genre: string = "session"
    public type: string = "start"

    constructor(public date: number, public tests: PacketTestStart[], public isAutoStart: boolean, public startedAt: number) {}
}

export class PacketSessionEnd implements Packet<PacketSessionEnd> {
    public genre: string = "session"
    public type: string = "end"

    constructor(public date: number, public tests: PacketTestEnd[], public startedAt: number, public finishedAt: number) {}
}
export function parsePacket(packet: string): Packet<any> | null
{
    const json = JSON.parse(packet)

    switch (json.genre) {
        case "session":
            switch (json.type) {
                case "start":
                    return new PacketSessionStart(json.date, json.scenario, json.isAutoStart, json.startedAt)
                case "end":
                    return new PacketSessionEnd(json.date, json.tests, json.isAutoStart, json.startedAt)
            }
            break
        case "test":
            switch (json.type) {
                case "start":
                    return new PacketTestStart(json.date, json.scenario)
                case "end":
                    return new PacketTestEnd(json.date, json.scenario, json.state, json.cause, json.startedAt, json.finishedAt)
            }
    }

    return null
}

export * from "./packets"
