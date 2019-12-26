package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response;

import java.util.List;

public class Discussion {
    private String id;

    private List<Note> notes;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<Note> getNotes() {
        return notes;
    }

    public void setNotes(List<Note> notes) {
        this.notes = notes;
    }
}
