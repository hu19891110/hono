/**
 * Copyright (c) 2016 Bosch Software Innovations GmbH.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Bosch Software Innovations GmbH - initial creation
 */
package org.eclipse.hono.example;

import javax.annotation.PostConstruct;

import org.eclipse.hono.client.HonoClient;
import org.eclipse.hono.client.HonoClient.HonoClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import io.vertx.core.Vertx;

/**
 * An example of using TelemetryClient for uploading and retrieving telemetry data to/from Hono.
 */
@SpringBootApplication
public class Application {

    private static final Logger LOG = LoggerFactory.getLogger(Application.class);

    private final Vertx vertx = Vertx.vertx();

    @Autowired
    private AppConfiguration config;

    @PostConstruct
    private void start() throws Exception {
        LOG.info("Starting TelemetryClient in role {}", config.role());
    }

    @Bean(destroyMethod="")
    public HonoClient client() {
        return HonoClientBuilder.newClient()
                .vertx(vertx())
                .host(config.host())
                .port(config.port())
                .user(config.user())
                .password(config.password())
                .pathSeparator(config.pathSeparator()).build();
    }

    @Bean
    public Vertx vertx() {
        return vertx;
    }

    public static void main(final String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
