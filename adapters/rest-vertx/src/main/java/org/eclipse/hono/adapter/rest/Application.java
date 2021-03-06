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
package org.eclipse.hono.adapter.rest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ServiceLocatorFactoryBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;

/**
 * The Hono REST adapter main application class.
 * <p>
 * This class uses Spring Boot for configuring the REST adapter's properties.
 * By default there will be as many instances of the REST adapter verticle created as there are CPU cores
 * available. The {@code hono.maxinstances} config property can be used to set the maximum number
 * of instances to create. This may be useful for executing tests etc.
 * </p>
 */
@ComponentScan
@Configuration
@EnableAutoConfiguration
public class Application {

    private static final Logger LOG = LoggerFactory.getLogger(Application.class);

    private final Vertx vertx = Vertx.vertx();
    @Value(value = "${hono.maxinstances:0}")
    private int maxInstances;
    @Value(value = "${hono.startuptimeout:20}")
    private int startupTimeout;
    @Autowired
    private RestAdapterFactory factory;

    @Bean
    public ServiceLocatorFactoryBean serviceLocator() {
        ServiceLocatorFactoryBean bean = new ServiceLocatorFactoryBean();
        bean.setServiceLocatorInterface(RestAdapterFactory.class);
        return bean;
    }

    @PostConstruct
    public void registerVerticles() {

        final CountDownLatch startupLatch = new CountDownLatch(1);
        final int instanceCount;
        if (maxInstances > 0 && maxInstances < Runtime.getRuntime().availableProcessors()) {
            instanceCount = maxInstances;
        } else {
            instanceCount = Runtime.getRuntime().availableProcessors();
        }

        deployVerticle(instanceCount).setHandler(done -> {
            if (done.succeeded()) {
                startupLatch.countDown();
            } else {
                LOG.error("could not start REST adapter", done.cause());
            }
        });

        try {
            if (startupLatch.await(startupTimeout, TimeUnit.SECONDS)) {
                LOG.info("REST adapter startup completed successfully");
            } else {
                LOG.error("startup timed out after {} seconds, shutting down ...", startupTimeout);
                shutdown();
            }
        } catch (InterruptedException e) {
            LOG.error("startup process has been interrupted, shutting down ...");
            Thread.currentThread().interrupt();
            shutdown();
        }
    }

    private Future<?> deployVerticle(int instanceCount) {
        @SuppressWarnings("rawtypes")
        List<Future> results = new ArrayList<>();
        for (int i = 1; i <= instanceCount; i++) {
            Future<String> result = Future.future();
            vertx.deployVerticle(factory.getRestAdapter(), result.completer());
            results.add(result);
        }
        return CompositeFuture.all(results);
    }

    @PreDestroy
    public void shutdown() {
        this.shutdown(startupTimeout, succeeded -> {
            // do nothing
        });
    }

    public void shutdown(final long maxWaitTime, final Handler<Boolean> shutdownHandler) {

        try {
            final CountDownLatch latch = new CountDownLatch(1);
            if (vertx != null) {
                vertx.close(r -> {
                    if (r.failed()) {
                        LOG.error("could not shut down REST adapter cleanly", r.cause());
                    }
                    latch.countDown();
                });
            }
            if (latch.await(maxWaitTime, TimeUnit.SECONDS)) {
                LOG.info("REST adapter has been shut down successfully");
                shutdownHandler.handle(Boolean.TRUE);
            } else {
                LOG.error("shut down of REST adapter timed out, aborting...");
                shutdownHandler.handle(Boolean.FALSE);
            }
        } catch (InterruptedException e) {
            LOG.error("shut down of REST adapter has been interrupted, aborting...");
            Thread.currentThread().interrupt();
            shutdownHandler.handle(Boolean.FALSE);
        }
    }

    public static void main(final String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
