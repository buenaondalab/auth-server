#!/bin/bash

./mvnw clean spring-boot:run -Dspring-boot.run.jvmArguments="spring.profiles.active=security,dev"

