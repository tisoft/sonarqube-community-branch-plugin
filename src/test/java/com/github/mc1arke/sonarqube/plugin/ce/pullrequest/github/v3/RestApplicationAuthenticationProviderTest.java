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
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.github.v3;

import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.github.RepositoryAuthenticationToken;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class RestApplicationAuthenticationProviderTest {

    @Test
    public void testTokenRetrievedHappyPath() throws IOException, GeneralSecurityException {
        UrlConnectionProvider urlProvider = mock(UrlConnectionProvider.class);
        Clock clock = Clock.fixed(Instant.ofEpochMilli(123456789L), ZoneId.systemDefault());

        String expectedAuthenticationToken = "expected authentication token";
        String projectPath = "project path";
        String expectedRepositoryId = "expected repository Id";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = mock(SecureRandom.class);
        AtomicInteger atomicInteger = new AtomicInteger(101);
        doAnswer(i -> {
            atomicInteger.getAndIncrement();
            byte[] bytes = i.getArgument(0);
            for (int a = 0; a < bytes.length; a++) {
                bytes[a] = (byte) (atomicInteger.get() + a);
            }
            return null;
        }).when(secureRandom).nextBytes(any());
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        URLConnection installationsUrlConnection = mock(URLConnection.class);
        doReturn(new ByteArrayInputStream(
                "[{\"repositories_url\": \"repositories_url\", \"access_tokens_url\": \"tokens_url\"}]"
                        .getBytes(StandardCharsets.UTF_8))).when(installationsUrlConnection).getInputStream();

        HttpURLConnection accessTokensUrlConnection = mock(HttpURLConnection.class);
        doReturn(new ByteArrayInputStream(
                ("{\"token\": \"" + expectedAuthenticationToken + "\"}").getBytes(StandardCharsets.UTF_8)))
                .when(accessTokensUrlConnection).getInputStream();
        doReturn(accessTokensUrlConnection).when(urlProvider).createUrlConnection("tokens_url");


        HttpURLConnection repositoriesUrlConnection = mock(HttpURLConnection.class);
        doReturn(new ByteArrayInputStream(
                ("{\"repositories\": [{\"node_id\": \"" + expectedRepositoryId + "\", \"full_name\": \"" + projectPath +
                 "\"}]}").getBytes(StandardCharsets.UTF_8))).when(repositoriesUrlConnection).getInputStream();
        doReturn(repositoriesUrlConnection).when(urlProvider).createUrlConnection("repositories_url");

        String apiUrl = "apiUrl";
        doReturn(installationsUrlConnection).when(urlProvider).createUrlConnection(eq(apiUrl + "/app/installations"));

        String appId = "appID";

        String apiPrivateKey;
        try (StringWriter stringWriter = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPrivate());
            pemWriter.flush();
            apiPrivateKey = stringWriter.toString();
        }

        RestApplicationAuthenticationProvider testCase = new RestApplicationAuthenticationProvider(clock, urlProvider);
        RepositoryAuthenticationToken result = testCase.getInstallationToken(apiUrl, appId, apiPrivateKey, projectPath);

        assertEquals(expectedAuthenticationToken, result.getAuthenticationToken());
        assertEquals(expectedRepositoryId, result.getRepositoryId());

        ArgumentCaptor<String> requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(installationsUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjEyMzQ0NiwiZXhwIjoxMjM1NjYsImlzcyI6ImFwcElEIn0.yMvAoUmmAHli-Mc-RidLbqlX2Cvc2RwPBwkgY6n1R2ZkV-IaY8uBO4s7pp0-3hcJvY4F7-UGnAi1dteGOODY8cOmx86DsSASJIHJ3wxaRxyLGOq2Z8A1KSWZj-F8O6wFf5pm2xzumm0gSSwdd3gQR0FiSn2TIHemjyoieNJfzvG2kgtHPBNIVaJcS8LqkVYBlvAujnAt1nQ1hIAbeQJyEmyVyb_NRMPQZZioBraobTlWdPWdnTQoNTWjmjcopIbUFw8s21uhMcDpA_6lS1iAZcoZKcpzMqsItEvQaiwYQWRccfZT69M_zWaVRjw2-eKsTuFXzumVyq3MnAoxy6R2Xw"),
                     requestPropertyArgumentCaptor.getAllValues());

        requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(accessTokensUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        verify(accessTokensUrlConnection).setRequestMethod("POST");
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjEyMzQ0NiwiZXhwIjoxMjM1NjYsImlzcyI6ImFwcElEIn0.yMvAoUmmAHli-Mc-RidLbqlX2Cvc2RwPBwkgY6n1R2ZkV-IaY8uBO4s7pp0-3hcJvY4F7-UGnAi1dteGOODY8cOmx86DsSASJIHJ3wxaRxyLGOq2Z8A1KSWZj-F8O6wFf5pm2xzumm0gSSwdd3gQR0FiSn2TIHemjyoieNJfzvG2kgtHPBNIVaJcS8LqkVYBlvAujnAt1nQ1hIAbeQJyEmyVyb_NRMPQZZioBraobTlWdPWdnTQoNTWjmjcopIbUFw8s21uhMcDpA_6lS1iAZcoZKcpzMqsItEvQaiwYQWRccfZT69M_zWaVRjw2-eKsTuFXzumVyq3MnAoxy6R2Xw"),
                     requestPropertyArgumentCaptor.getAllValues());

        requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(repositoriesUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        verify(repositoriesUrlConnection).setRequestMethod("GET");
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer " + expectedAuthenticationToken),
                     requestPropertyArgumentCaptor.getAllValues());
    }

    @Test
    public void testExceptionOnNoMatchingToken() throws IOException, GeneralSecurityException {
        UrlConnectionProvider urlProvider = mock(UrlConnectionProvider.class);
        Clock clock = Clock.fixed(Instant.ofEpochMilli(123456789L), ZoneId.systemDefault());

        String expectedAuthenticationToken = "expected authentication token";
        String projectPath = "project path";
        String expectedRepositoryId = "expected repository Id";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = mock(SecureRandom.class);
        AtomicInteger atomicInteger = new AtomicInteger();
        doAnswer(i -> {
            atomicInteger.getAndIncrement();
            byte[] bytes = i.getArgument(0);
            for (int a = 0; a < bytes.length; a++) {
                bytes[a] = (byte) atomicInteger.get();
            }
            return null;
        }).when(secureRandom).nextBytes(any());
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        URLConnection installationsUrlConnection = mock(URLConnection.class);
        doReturn(new ByteArrayInputStream(
                "[{\"repositories_url\": \"repositories_url\", \"access_tokens_url\": \"tokens_url\"}]"
                        .getBytes(StandardCharsets.UTF_8))).when(installationsUrlConnection).getInputStream();

        HttpURLConnection accessTokensUrlConnection = mock(HttpURLConnection.class);
        doReturn(new ByteArrayInputStream(
                ("{\"token\": \"" + expectedAuthenticationToken + "\"}").getBytes(StandardCharsets.UTF_8)))
                .when(accessTokensUrlConnection).getInputStream();
        doReturn(accessTokensUrlConnection).when(urlProvider).createUrlConnection("tokens_url");


        HttpURLConnection repositoriesUrlConnection = mock(HttpURLConnection.class);
        doReturn(new ByteArrayInputStream(("{\"repositories\": [{\"node_id\": \"" + expectedRepositoryId +
                                           "\", \"full_name\": \"different_path\"}]}")
                                                  .getBytes(StandardCharsets.UTF_8))).when(repositoriesUrlConnection)
                .getInputStream();
        doReturn(repositoriesUrlConnection).when(urlProvider).createUrlConnection("repositories_url");

        String apiUrl = "apiUrl";
        doReturn(installationsUrlConnection).when(urlProvider).createUrlConnection(eq(apiUrl + "/app/installations"));

        String appId = "appID";

        String apiPrivateKey;
        try (StringWriter stringWriter = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPrivate());
            pemWriter.flush();
            apiPrivateKey = stringWriter.toString();
        }

        RestApplicationAuthenticationProvider testCase = new RestApplicationAuthenticationProvider(clock, urlProvider);
        assertThatThrownBy(() -> testCase.getInstallationToken(apiUrl, appId, apiPrivateKey, projectPath)).hasMessage(
                "No token could be found with access to the requested repository with the given application ID and key")
                .isExactlyInstanceOf(IllegalStateException.class);

        ArgumentCaptor<String> requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(installationsUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjEyMzQ0NiwiZXhwIjoxMjM1NjYsImlzcyI6ImFwcElEIn0.jZ9Oak1zMc2CfkartTRYBfGeXkLcO3eowSjkr3DNWBkvgQo8DUPuUNSd4qAZmk87onYBSyLL-TT7vafeerVcD-EVOZxdeXEmev8IbDoBKMNnGOJAfCAAMdu1snLvHBV9RkgDo3low--GI_C-PkOtM5BkuWS015AsoK1NLTu1KZLSpVlcHMiE5h1acBDifx_rQf97TAPB45cwpBibxokygQYf3-g_nWJTCIJAjJFlOFoR60C6xA8LBwS_6kLtrrMsCw3x9Kn9q1PNDapyOJaCid10sCEedQXfRmK3o8k603mlY8POHLTSwK0VCZNtRkIYzf7kPlCRDJgoc7Ab99W2Jw"),
                     requestPropertyArgumentCaptor.getAllValues());

        requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(accessTokensUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        verify(accessTokensUrlConnection).setRequestMethod("POST");
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjEyMzQ0NiwiZXhwIjoxMjM1NjYsImlzcyI6ImFwcElEIn0.jZ9Oak1zMc2CfkartTRYBfGeXkLcO3eowSjkr3DNWBkvgQo8DUPuUNSd4qAZmk87onYBSyLL-TT7vafeerVcD-EVOZxdeXEmev8IbDoBKMNnGOJAfCAAMdu1snLvHBV9RkgDo3low--GI_C-PkOtM5BkuWS015AsoK1NLTu1KZLSpVlcHMiE5h1acBDifx_rQf97TAPB45cwpBibxokygQYf3-g_nWJTCIJAjJFlOFoR60C6xA8LBwS_6kLtrrMsCw3x9Kn9q1PNDapyOJaCid10sCEedQXfRmK3o8k603mlY8POHLTSwK0VCZNtRkIYzf7kPlCRDJgoc7Ab99W2Jw"),
                     requestPropertyArgumentCaptor.getAllValues());

        requestPropertyArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(repositoriesUrlConnection, times(2))
                .setRequestProperty(requestPropertyArgumentCaptor.capture(), requestPropertyArgumentCaptor.capture());
        verify(repositoriesUrlConnection).setRequestMethod("GET");
        assertEquals(Arrays.asList("Accept", "application/vnd.github.machine-man-preview+json", "Authorization",
                                   "Bearer " + expectedAuthenticationToken),
                     requestPropertyArgumentCaptor.getAllValues());

    }

    @Test
    public void testDefaultParameters() {
        Clock clock = mock(Clock.class);
        assertThat(new RestApplicationAuthenticationProvider(clock, new DefaultUrlConnectionProvider()))
                .usingRecursiveComparison().isEqualTo(new RestApplicationAuthenticationProvider(clock));
    }
}
