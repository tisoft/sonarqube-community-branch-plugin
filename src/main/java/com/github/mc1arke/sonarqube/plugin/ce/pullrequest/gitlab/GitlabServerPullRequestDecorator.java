/*
 * Copyright (C) 2019 Michael Clarke
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.PostAnalysisIssueVisitor;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.PullRequestBuildStatusDecorator;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Commit;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.CommitDiscussion;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Discussion;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Note;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.User;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.sonar.api.ce.posttask.Analysis;
import org.sonar.api.ce.posttask.PostProjectAnalysisTask;
import org.sonar.api.ce.posttask.QualityGate;
import org.sonar.api.config.Configuration;
import org.sonar.api.issue.Issue;
import org.sonar.api.measures.CoreMetrics;
import org.sonar.api.platform.Server;
import org.sonar.api.rules.RuleType;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.ce.task.projectanalysis.component.ConfigurationRepository;
import org.sonar.ce.task.projectanalysis.component.TreeRootHolder;
import org.sonar.ce.task.projectanalysis.measure.Measure;
import org.sonar.ce.task.projectanalysis.measure.MeasureRepository;
import org.sonar.ce.task.projectanalysis.metric.MetricRepository;
import org.sonar.core.issue.DefaultIssue;
import org.sonar.server.measure.Rating;

import static org.sonar.api.rule.Severity.BLOCKER;
import static org.sonar.api.rule.Severity.CRITICAL;
import static org.sonar.api.rule.Severity.INFO;
import static org.sonar.api.rule.Severity.MAJOR;
import static org.sonar.api.rule.Severity.MINOR;

public class GitlabServerPullRequestDecorator implements PullRequestBuildStatusDecorator {

    private static final Logger LOGGER = Loggers.get(GitlabServerPullRequestDecorator.class);
    private static final List<String> OPEN_ISSUE_STATUSES =
            Issue.STATUSES.stream().filter(s -> !Issue.STATUS_CLOSED.equals(s) && !Issue.STATUS_RESOLVED.equals(s))
                    .collect(Collectors.toList());

    private static final String NEW_LINE = "\n\n";


    private final ConfigurationRepository configurationRepository;
    private final Server server;
    private final MetricRepository metricRepository;
    private final MeasureRepository measureRepository;
    private final TreeRootHolder treeRootHolder;
    private final PostAnalysisIssueVisitor postAnalysisIssueVisitor;
    private String status;

    public GitlabServerPullRequestDecorator(Server server, ConfigurationRepository configurationRepository,
                                               MeasureRepository measureRepository, MetricRepository metricRepository,
                                               TreeRootHolder treeRootHolder,
                                               PostAnalysisIssueVisitor postAnalysisIssueVisitor) {
        super();
        this.configurationRepository = configurationRepository;
        this.server = server;
        this.measureRepository = measureRepository;
        this.metricRepository = metricRepository;
        this.treeRootHolder = treeRootHolder;
        this.postAnalysisIssueVisitor = postAnalysisIssueVisitor;
    }

    @Override
    public void decorateQualityGateStatus(PostProjectAnalysisTask.ProjectAnalysis projectAnalysis) {
        LOGGER.info("starting to analyze with " + projectAnalysis.toString());
        Optional<Analysis> optionalAnalysis = projectAnalysis.getAnalysis();
        if (!optionalAnalysis.isPresent()) {
            LOGGER.warn(
                    "No analysis results were created for this project analysis. This is likely to be due to an earlier failure");
            return;
        }

        Analysis analysis = optionalAnalysis.get();

        Optional<String> revision = analysis.getRevision();
        if (!revision.isPresent()) {
            LOGGER.warn("No commit details were submitted with this analysis. Check the project is committed to Git");
            return;
        }

        if (null == projectAnalysis.getQualityGate()) {
            LOGGER.warn("No quality gate was found on the analysis, so no results are available");
            return;
        }

        try {
            Configuration configuration = configurationRepository.getConfiguration();
            final String hostURL = getMandatoryProperty("sonar.pullrequest.gitlab.url", configuration);
            final String apiToken = getMandatoryProperty("sonar.pullrequest.gitlab.token", configuration);
            final String repositorySlug = getMandatoryProperty("sonar.pullrequest.gitlab.repositorySlug", configuration);
            final String pullRequestId = projectAnalysis.getBranch().get().getName().get();

            final boolean summaryCommentEnabled = Boolean.parseBoolean(getMandatoryProperty("sonar.pullrequest.summary.comment.enabled", configuration));
            final boolean fileCommentEnabled = Boolean.parseBoolean(getMandatoryProperty("sonar.pullrequest.file.comment.enabled", configuration));
            final boolean deleteCommentsEnabled = Boolean.parseBoolean(getMandatoryProperty("sonar.pullrequest.delete.comments.enabled", configuration));

            final String restURL = String.format("%s/api/v4", hostURL);
            final String userURL = restURL + "/user";
            final String projectURL = restURL + String.format("/projects/%s", URLEncoder.encode(repositorySlug, StandardCharsets.UTF_8.name()));
            final String statusUrl = projectURL + String.format("/statuses/%s", revision.get());
            final String commitURL = projectURL + String.format("/repository/commits/%s", revision.get());
            final String commitCommentUrl = commitURL + "/comments";
            final String mergeRequestURl = projectURL + String.format("/merge_requests/%s", pullRequestId);
            final String prCommitsURL = mergeRequestURl + "/commits";


            LOGGER.info(String.format("Status url is: %s ", statusUrl));
            LOGGER.info(String.format("Commit comment url is: %s ", commitCommentUrl));
            LOGGER.info(String.format("PR commits url is: %s ", prCommitsURL));
            LOGGER.info(String.format("User url is: %s ", userURL));

            Map<String, String> headers = new HashMap<>();
            headers.put("PRIVATE-TOKEN", apiToken);
            headers.put("Accept", "application/json");

            User user=getUser(userURL, headers);
            LOGGER.info(String.format("Using user: %s ", user.getUsername()));

            List<Commit> commits = getMRCommits(prCommitsURL, headers, deleteCommentsEnabled);
            LOGGER.info(String.format("Commits in MR: %s ", commits.stream().map(Commit::getId).collect(Collectors.joining(", "))));
            List<CommitDiscussion> commitDiscussions = new ArrayList<>();
            for (Commit commit : commits) {
                getCommitDiscussions(projectURL + String.format("/repository/commits/%s/discussions", commit.getId()), headers, deleteCommentsEnabled)
                        .stream()
                        .map(d -> new CommitDiscussion(commit, d))
                        .forEach(commitDiscussions::add);
            }
            LOGGER.info(String.format("Commit Discussions in MR: %s ", commitDiscussions
                    .stream()
                    .map(CommitDiscussion::getDiscussion)
                    .map(Discussion::getId)
                    .collect(Collectors.joining(", "))));

            for (CommitDiscussion commitDiscussion : commitDiscussions) {
                for (Note note : commitDiscussion.getDiscussion().getNotes()) {
                    if (note.getAuthor() != null && note.getAuthor().getUsername().equals(user.getUsername())) {
                        //delete only our own comments
                        deleteCommitDiscussionNote(projectURL + String.format("/repository/commits/%s/discussions/%s/notes/%s",
                                commitDiscussion.getCommit().getId(),
                                commitDiscussion.getDiscussion().getId(),
                                note.getId()),
                                headers, deleteCommentsEnabled);
                    }
                }
            }

            String status =
                    (QualityGate.Status.OK == projectAnalysis.getQualityGate().getStatus() ? "Passed" : "Failed");

            List<QualityGate.Condition> failedConditions = projectAnalysis.getQualityGate().getConditions().stream()
                    .filter(c -> c.getStatus() != QualityGate.EvaluationStatus.OK).collect(Collectors.toList());

            QualityGate.Condition newCoverageCondition = projectAnalysis.getQualityGate().getConditions().stream()
                    .filter(c -> CoreMetrics.NEW_COVERAGE_KEY.equals(c.getMetricKey())).findFirst()
                    .orElseThrow(() -> new IllegalStateException("Could not find New Coverage Condition in analysis"));
            String coverageValue = newCoverageCondition.getStatus().equals(QualityGate.EvaluationStatus.NO_VALUE) ? "0" : newCoverageCondition.getValue();

            String estimatedCoverage = measureRepository
                    .getRawMeasure(treeRootHolder.getRoot(), metricRepository.getByKey(CoreMetrics.COVERAGE_KEY))
                    .map(Measure::getData).orElse("0");

            QualityGate.Condition newDuplicationCondition = projectAnalysis.getQualityGate().getConditions().stream()
                    .filter(c -> CoreMetrics.NEW_DUPLICATED_LINES_DENSITY_KEY.equals(c.getMetricKey())).findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "Could not find New Duplicated Lines Condition in analysis"));
            String estimatedDuplications = measureRepository.getRawMeasure(treeRootHolder.getRoot(), metricRepository
                    .getByKey(CoreMetrics.DUPLICATED_LINES_KEY)).map(Measure::getData).orElse("0");


            List<DefaultIssue> openIssues = postAnalysisIssueVisitor.getIssues().stream().filter(i -> OPEN_ISSUE_STATUSES.contains(i.status())).collect(Collectors.toList());
            Map<RuleType, Long> issueCounts = Arrays.stream(RuleType.values()).collect(Collectors.toMap(k -> k,
                                                                                                        k -> openIssues
                                                                                                                .stream()
                                                                                                                .filter(i -> k ==
                                                                                                                             i.type())
                                                                                                                .count()));

            String summaryComment = String.format("%s %s", status, NEW_LINE) +
                    String.format("%s %s", failedConditions.stream().map(c -> "- " + format(c)).collect(Collectors.joining(NEW_LINE)), NEW_LINE) +
                    String.format("# Analysis Details %s", NEW_LINE) +
                    String.format("## %s Issues %s", issueCounts.values().stream().mapToLong(l -> l).sum(), NEW_LINE) +
                    String.format(" - %s %s", pluralOf(issueCounts.get(RuleType.BUG), "Bug", "Bugs"), NEW_LINE) +
                    String.format(" - %s %s", pluralOf(issueCounts.get(RuleType.VULNERABILITY), "Vulnerability", "Vulnerabilities"), NEW_LINE) +
                    String.format(" - %s %s", pluralOf(issueCounts.get(RuleType.SECURITY_HOTSPOT), "Security issue", "Security issues"), NEW_LINE) +
                    String.format(" - %s %s", pluralOf(issueCounts.get(RuleType.CODE_SMELL), "Code Smell", "Code Smells"), NEW_LINE) +
                    String.format("## Coverage and Duplications %s", NEW_LINE) +
                    String.format(" - %s%% Coverage (%s%% Estimated after merge) %s", coverageValue, estimatedCoverage, NEW_LINE) +
                    String.format(" - %s%% Duplicated Code (%s%% Estimated after merge) %s", newDuplicationCondition.getValue(), estimatedDuplications, NEW_LINE);
            List<NameValuePair> summaryContentParams = Collections.singletonList(new BasicNameValuePair("note", summaryComment));

            postStatus(statusUrl, headers, projectAnalysis, summaryComment, coverageValue, true);

            postCommitComment(commitCommentUrl, headers, summaryContentParams, summaryCommentEnabled);

            for (DefaultIssue issue : openIssues) {
                StringBuilder fileComment = new StringBuilder();
                final String line = issue.getLine()==null?"0":String.valueOf(issue.getLine());
                fileComment.append(String.format("Location: %s/%s/blob/%s/%s#L%s %s", hostURL, repositorySlug, revision.get(), postAnalysisIssueVisitor.getIssueMap().get(issue), line, NEW_LINE));
                fileComment.append(String.format("Type: %s %s", issue.type().name(), NEW_LINE));
                fileComment.append(String.format("Severity: %s %s %s", getSeverityEmoji(issue.severity()), issue.severity(), NEW_LINE));
                fileComment.append(String.format("Message: %s %s", issue.getMessage(), NEW_LINE));
                Long effort = issue.effortInMinutes();
                if (effort != null)
                {
                    fileComment.append(String.format("Duration (min): %s %s", effort, NEW_LINE));
                }
                String resolution = issue.resolution();
                if (StringUtils.isNotBlank(resolution))
                {
                    fileComment.append(String.format("Resolution: %s %s", resolution, NEW_LINE));
                }
                LOGGER.info(issue.toString());
                List<NameValuePair> fileContentParams = Arrays.asList(new BasicNameValuePair("note", fileComment.toString()),
                        new BasicNameValuePair("path", postAnalysisIssueVisitor.getIssueMap().get(issue)),
                        new BasicNameValuePair("line", line),
                        new BasicNameValuePair("line_type", "new"));
                postCommitComment(commitCommentUrl, headers, fileContentParams, fileCommentEnabled);
        }
        } catch (IOException ex) {
            throw new IllegalStateException("Could not decorate Pull Request on Gitlab Server", ex);
        }

    }
    private User getUser(String userURL, Map<String, String> headers) throws IOException {
        HttpGet httpGet = new HttpGet(userURL);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpGet.addHeader(entry.getKey(), entry.getValue());
        }
        HttpResponse httpResponse = HttpClients.createDefault().execute(httpGet);
        if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 200) {
            LOGGER.error(httpResponse.toString());
            LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
            throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
        } else if (null != httpResponse) {
            LOGGER.debug(httpResponse.toString());
            HttpEntity entity = httpResponse.getEntity();
            User user = new ObjectMapper()
                    .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, true)
                    .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .readValue(IOUtils.toString(entity.getContent()), User.class);

            LOGGER.info("User received");

            return user;
        } else {
            throw new IOException("No response reveived");
        }
    }

    private List<Commit> getMRCommits(String prCommitsURL, Map<String, String> headers, boolean sendRequest) throws IOException {
        //https://docs.gitlab.com/ee/api/merge_requests.html#get-single-mr-commits
        HttpGet httpGet = new HttpGet(prCommitsURL);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpGet.addHeader(entry.getKey(), entry.getValue());
        }

        List<Commit> commits = new ArrayList<>();

        if (sendRequest) {
            HttpResponse httpResponse = HttpClients.createDefault().execute(httpGet);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 200) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                HttpEntity entity = httpResponse.getEntity();
                List<Commit> pagedCommits = new ObjectMapper()
                        .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, true)
                        .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                        .readValue(IOUtils.toString(entity.getContent()), new TypeReference<List<Commit>>() {
                        });
                commits.addAll(pagedCommits);
                LOGGER.info("Commits received");
                String nextURL = getNextUrl(httpResponse);
                if (nextURL != null) {
                    LOGGER.info("Getting next page");
                    commits.addAll(getMRCommits(nextURL, headers, sendRequest));
                }
            }
        }
        return commits;
    }

    private List<Discussion> getCommitDiscussions(String commitDiscussionURL, Map<String, String> headers, boolean sendRequest) throws IOException {
        //https://docs.gitlab.com/ee/api/discussions.html#list-project-commit-discussion-items
        HttpGet httpGet = new HttpGet(commitDiscussionURL);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpGet.addHeader(entry.getKey(), entry.getValue());
        }

        List<Discussion> discussions = new ArrayList<>();

        if (sendRequest) {
            HttpResponse httpResponse = HttpClients.createDefault().execute(httpGet);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 200) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                HttpEntity entity = httpResponse.getEntity();
                List<Discussion> pagedDiscussions = new ObjectMapper()
                        .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, true)
                        .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                        .readValue(IOUtils.toString(entity.getContent()), new TypeReference<List<Discussion>>() {
                        });
                discussions.addAll(pagedDiscussions);
                LOGGER.info("Commit discussions received");
                String nextURL = getNextUrl(httpResponse);
                if (nextURL != null) {
                    LOGGER.info("Getting next page");
                    discussions.addAll(getCommitDiscussions(nextURL, headers, sendRequest));
                }
            }
        }
        return discussions;
    }

    private void deleteCommitDiscussionNote(String commitDiscussionNoteURL, Map<String, String> headers, boolean sendRequest) throws IOException {
        //https://docs.gitlab.com/ee/api/discussions.html#delete-a-commit-thread-note
        HttpDelete httpDelete = new HttpDelete(commitDiscussionNoteURL);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpDelete.addHeader(entry.getKey(), entry.getValue());
        }

        if (sendRequest) {
            HttpResponse httpResponse = HttpClients.createDefault().execute(httpDelete);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 204) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                LOGGER.info("Commit discussions note deleted");
            }
        }
    }

    private void postCommitComment(String commitCommentUrl, Map<String, String> headers, List<NameValuePair> params, boolean sendRequest) throws IOException {
        //https://docs.gitlab.com/ee/api/commits.html#post-comment-to-commit
        HttpPost httpPost = new HttpPost(commitCommentUrl);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpPost.addHeader(entry.getKey(), entry.getValue());
        }
        httpPost.setEntity(new UrlEncodedFormEntity(params));

        if (sendRequest) {
            HttpResponse httpResponse = HttpClients.createDefault().execute(httpPost);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 201) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                LOGGER.info("Comment posted");
            }
        }
    }

    protected void postStatus(String statusPostUrl, Map<String, String> headers, PostProjectAnalysisTask.ProjectAnalysis projectAnalysis, String comment, String coverage, boolean sendRequest) throws IOException{
        //See https://docs.gitlab.com/ee/api/commits.html#post-the-build-status-to-a-commit
        statusPostUrl += "?name=SonarQube";
        status = (projectAnalysis.getQualityGate().getStatus() == QualityGate.Status.OK ? "success" : "failed");
        statusPostUrl += "&state=" + status;
        statusPostUrl += "&target_url=" + URLEncoder.encode(String.format("%s/dashboard?id=%s&pullRequest=%s", server.getPublicRootUrl(),
                URLEncoder.encode(projectAnalysis.getProject().getKey(),
                        StandardCharsets.UTF_8.name()), URLEncoder
                        .encode(projectAnalysis.getBranch().get().getName().get(),
                                StandardCharsets.UTF_8.name())), StandardCharsets.UTF_8.name());
        //statusPostUrl+="&description="+URLEncoder.encode(comment, StandardCharsets.UTF_8.name());
        statusPostUrl+="&coverage="+coverage;
        //TODO: add pipelineId if we have it

        HttpPost httpPost = new HttpPost(statusPostUrl);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpPost.addHeader(entry.getKey(), entry.getValue());
        }
        if (sendRequest) {
            HttpResponse httpResponse = HttpClients.createDefault().execute(httpPost);
            if (null != httpResponse && httpResponse.toString().contains("Cannot transition status")) {
                // Workaround for https://gitlab.com/gitlab-org/gitlab-ce/issues/25807
                LOGGER.debug("Transition status is already {}", status);
            } else if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 201) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), "UTF-8"));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                LOGGER.info("Comment posted");
            }
        }
   }

    private String getSeverityEmoji(String severity) {
        String icon;
        switch (severity)
        {
            case BLOCKER: icon = ":arrow_double_up:"; break;
            case CRITICAL: icon = ":arrow_up:"; break;
            case MAJOR: icon = ":arrow_right:"; break;
            case MINOR: icon = ":arrow_down:"; break;
            case INFO: icon = ":arrow_double_down:"; break;
            default: icon = StringUtils.EMPTY;
        }
        return icon;
    }

    private static String pluralOf(long value, String singleLabel, String multiLabel) {
        return value + " " + (1 == value ? singleLabel : multiLabel);
    }


    private static String getMandatoryProperty(String propertyName, Configuration configuration) {
        return configuration.get(propertyName).orElseThrow(() -> new IllegalStateException(
                String.format("%s must be specified in the project configuration", propertyName)));
    }

    private static String format(QualityGate.Condition condition) {
        org.sonar.api.measures.Metric<?> metric = CoreMetrics.getMetric(condition.getMetricKey());
        if (metric.getType() == org.sonar.api.measures.Metric.ValueType.RATING) {
            return String
                    .format("%s %s (%s %s)", Rating.valueOf(Integer.parseInt(condition.getValue())), metric.getName(),
                            condition.getOperator() == QualityGate.Operator.GREATER_THAN ? "is worse than" :
                            "is better than", Rating.valueOf(Integer.parseInt(condition.getErrorThreshold())));
        } else {
            return String.format("%s %s (%s %s)", condition.getStatus().equals(QualityGate.EvaluationStatus.NO_VALUE) ? "0" : condition.getValue(), metric.getName(),
                                 condition.getOperator() == QualityGate.Operator.GREATER_THAN ? "is greater than" :
                                 "is less than", condition.getErrorThreshold());
        }
    }

    public String getNextUrl(HttpResponse httpResponse) {
        Header linkHeader = httpResponse.getFirstHeader("Link");
        if (linkHeader != null) {
            Matcher matcher = Pattern.compile("<([^\\>]+)>;[\\s]*rel=\"([a-z]+)\"").matcher(linkHeader.getValue());
            while (matcher.find()) {
                if (matcher.group(2).equals("next")) {
                    //found the next rel return the URL
                    return matcher.group(1);
                }
            }
        }
        return null;
    }

    @Override
    public String name() {
        return "GitlabServer";
    }
}