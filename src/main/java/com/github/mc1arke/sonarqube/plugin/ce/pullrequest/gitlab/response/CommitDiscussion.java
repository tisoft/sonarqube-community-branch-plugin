package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response;

public class CommitDiscussion {
    private final Commit commit;

    private final Discussion discussion;

    public CommitDiscussion(Commit commit, Discussion discussion) {
        this.commit = commit;
        this.discussion = discussion;
    }

    public Commit getCommit() {
        return commit;
    }

    public Discussion getDiscussion() {
        return discussion;
    }
}
