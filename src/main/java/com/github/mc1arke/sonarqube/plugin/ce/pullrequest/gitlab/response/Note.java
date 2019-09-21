package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response;

public class Note {
    private long id;

    private User author;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public User getAuthor() {
        return author;
    }

    public void setAuthor(User author) {
        this.author = author;
    }
}
