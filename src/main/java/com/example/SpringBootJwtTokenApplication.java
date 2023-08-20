package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan("com.example.properties")
public class SpringBootJwtTokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootJwtTokenApplication.class, args);
	}

}
