import {getArguments} from "../../utils";
import type {IssueComment, Maybe, Repository} from "@octokit/graphql-schema";
import type {GitHub} from "@actions/github/lib/utils";

const COMMENT_IDENTIFIER = `<!-- ### Scenamatica plugin analysis report for MC ${getArguments().mcVersion} ### -->`;
const COMMENT_AUTHOR_LOGIN = "github-actions"

export const findFirstReportComment = async (
    octokit: InstanceType<typeof GitHub>,
    owner: string,
    repo: string,
    number: number
): Promise<IssueComment | undefined> => {
    const query = `
        query ($repo: String!, $owner: String!, $number: Int!) {
            repository(name: $repo, owner: $owner) {
                pullRequest(number: $number) {
                    comments(first: 25) {
                        nodes {
                            id
                            author {
                                login
                            }
                            body
                        }
                    }
                }
            }
        }
    `

    const response = await octokit.graphql<{repository: Repository}>(
        query,
        {
            repo,
            owner,
            number
        }
    )

    if (!response.repository.pullRequest) {
        return undefined
    }

    const comment = response.repository.pullRequest.comments.nodes?.find(isScenamaticaReport)

    return comment ?? undefined

}

export const upsertReport = async (
    octokit: InstanceType<typeof GitHub>,
    owner: string,
    repo: string,
    number: number,
    report: string
) => {
    const comment = await findFirstReportComment(octokit, owner, repo, number)

    await (comment ? updateOldComment(octokit, owner, repo, comment.id, report) : postNewComment(octokit, owner, repo, number, report));
}

const postNewComment = async (octokit: InstanceType<typeof GitHub>,
                              owner: string,
                              repo: string,
                              number: number,
                              body: string
) => {
    const fullBody = `${COMMENT_IDENTIFIER} \n${body}`

    await octokit.issues.createComment({
        owner,
        repo,
        issue_number: number,
        body: fullBody
    })
}

const updateOldComment = async (octokit: InstanceType<typeof GitHub>,
                                owner: string,
                                repo: string,
                                commentId: string,
                                body: string
) => {
    const fullBody = `${COMMENT_IDENTIFIER} \n${body}`

    const query = `
        mutation ($input: UpdateIssueCommentInput!) {
            updateIssueComment(input: $input) {
                issueComment {
                    id
                    body
                }
            }
        }
    `

    await octokit.graphql(
        query,
        {
            input: {
                id: commentId,
                body: fullBody
            }
        })
}

const isScenamaticaReport = (comment: Maybe<IssueComment>) => {
    if (!comment) {
        return false;
    }

    return comment.author?.login === COMMENT_AUTHOR_LOGIN
        && comment.body.includes(COMMENT_IDENTIFIER);
}
