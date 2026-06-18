package com.apt.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.concurrent.Executors;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;

/**
 * AptPlatformApplication — the Spring Boot entry point.
 *
 * Component scan spans all our modules (com.apt.*) so Spring
 * discovers @Service, @Component, @Repository beans everywhere.
 *
 * Key annotations explained:
 *
 * @SpringBootApplication:
 *   Combines @Configuration + @ComponentScan + @EnableAutoConfiguration.
 *   Auto-configures Kafka, MongoDB, JPA, Redis from application.yml.
 *
 * @EnableScheduling:
 *   Activates the @Scheduled annotation in NetworkLogSimulator.
 *   Without this, the simulator won't fire.
 *
 * @EnableAsync:
 *   Allows @Async methods to run on a thread pool.
 *   Used by the detection engine for non-blocking ML scoring.
 *
 * Project Loom Virtual Threads (Java 21):
 *   The Tomcat customizer below switches Tomcat from OS threads
 *   to virtual threads. Each HTTP request now runs on a lightweight
 *   virtual thread (costing ~1KB vs 1MB for OS threads).
 *   This allows handling 10,000+ concurrent connections on standard hardware.
 *   The code looks exactly the same — Spring handles the switch transparently.
 */
@Slf4j
@SpringBootApplication
@ComponentScan(basePackages = "com.apt")       // Scan all modules
@EntityScan(basePackages = "com.apt.core.model") // JPA entities in core module
@EnableJpaRepositories(basePackages = {
    "com.apt.api.repository",                  // API user repositories
    "com.apt.detection"                        // Detection engine repositories (Week 2)
})
@EnableMongoRepositories(basePackages = "com.apt.ingestion.repository")
@EnableScheduling   // Activates @Scheduled in NetworkLogSimulator
@EnableAsync        // Activates @Async for non-blocking detection
public class AptPlatformApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(AptPlatformApplication.class);
        app.run(args);
    }

    /**
     * Project Loom: replace Tomcat's OS thread pool with virtual threads.
     *
     * Before Loom: 200 OS threads = 200MB overhead, limited concurrency
     * After Loom:  Millions of virtual threads, each ~1KB, same code
     *
     * This is critical for handling the WebSocket connections from
     * many concurrent SOC dashboard users.
     */
    @Bean
    public TomcatProtocolHandlerCustomizer<?> virtualThreadsCustomizer() {
        return protocolHandler ->
            protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }
}
