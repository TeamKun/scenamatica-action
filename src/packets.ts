// @ts-nocheck

export class Packet<T extends Packet<T>> {
    public constructor(public genre: string, public type: string, public date: number) {}
}

export interface Scenario {
    name: string
    description?: string
}

export class PacketTestStart implements Packet<PacketTestStart> {
    public genre = "test"

    public type = "start"

    public constructor(public date: number, public scenario: Scenario) {}
}

export enum TestState {
    STAND_BY = "STAND_BY",
    CONTEXT_PREPARING = "CONTEXT_PREPARING",
    STARTING = "STARTING",
    RUNNING_BEFORE = "RUNNING_BEFORE",
    RUNNING_MAIN = "RUNNING_MAIN",
    RUNNING_AFTER = "RUNNING_AFTER",
    FINISHED = "FINISHED",
}

export enum TestResultCause {
    PASSED = "PASSED",

    CONTEXT_PREPARATION_FAILED = "CONTEXT_PREPARATION_FAILED",
    ACTION_EXECUTION_FAILED = "ACTION_EXECUTION_FAILED",
    ACTION_EXPECTATION_JUMPED = "ACTION_EXPECTATION_JUMPED",
    SCENARIO_TIMED_OUT = "SCENARIO_TIMED_OUT",
    ILLEGAL_CONDITION = "ILLEGAL_CONDITION",

    INTERNAL_ERROR = "INTERNAL_ERROR",
    CANCELLED = "CANCELLED",
    SKIPPED = "SKIPPED",
}

export class PacketTestEnd implements Packet<PacketTestEnd> {
    public genre = "test"

    public type = "end"

    public constructor(
        public date: number,
        public scenario: Scenario,
        public state: TestState,
        public cause: TestResultCause,
        public startedAt: number,
        public finishedAt: number,
        public attemptOf?: number
    ) {}
}

export class PacketSessionStart implements Packet<PacketSessionStart> {
    public genre = "session"

    public type = "start"

    public constructor(
        public date: number,
        public tests: PacketTestStart[],
        public isAutoStart: boolean,
        public startedAt: number,
    ) {}
}

export class PacketSessionEnd implements Packet<PacketSessionEnd> {
    public genre = "session"

    public type = "end"

    public constructor(
        public date: number,
        public results: PacketTestEnd[],
        public startedAt: number,
        public finishedAt: number,
    ) {}
}

export class PacketScenamaticaError implements Packet<PacketScenamaticaError> {
    public genre = "general"

    public type = "error"
    public constructor(public date: number, public exception: string, public message: string, public stackTrace: string[], public causedBy?: PacketScenamaticaError = null) {}
}

export class PacketActionRelated implements Packet<PacketActionRelated> {
    public genre = "action"
}

export const parsePacket = (
    packet: string,
): Packet<PacketSessionEnd | PacketSessionStart | PacketTestEnd | PacketTestStart> | null => {
    const json: unknown = JSON.parse(packet)

    switch (json.genre) {
        case "session": {
            switch (json.type) {
                case "start": {
                    return new PacketSessionStart(json.date, json.tests, json.isAutoStart, json.startedAt)
                }

                case "end": {
                    return new PacketSessionEnd(json.date, json.results, json.startedAt, json.date)
                }
            }

            break
        }
        case "test": {
            switch (json.type) {
                case "start": {
                    return new PacketTestStart(json.date, json.scenario)
                }

                case "end": {
                    return new PacketTestEnd(
                        json.date,
                        json.scenario,
                        json.state,
                        json.cause,
                        json.startedAt,
                        json.finishedAt,
                        json.attemptOf,
                    )
                }
            }

            break
        }

        case "general": {
            switch (json.type) {
                case "error": {
                    return new PacketScenamaticaError(json.date, json.exception, json.message, json.stackTrace)
                }
            }

            break
        }
        case "action": {
            return new PacketActionRelated()
        }
    }

    return null
}

export * from "./packets"
