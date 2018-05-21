# Bumo Java encryption

## Introduction
Java developers can easily realize the encryption module of Bumo block chain through Bumo Java Encryption. And you can complete the installation of the SDK in Maven or by downloading the jar package in a few minutes.

1. [docs](/docs) are the usage documentations for the Bumo Java Encryption.
2. [examples](/examples) are some examples of a project based on Maven.
3. [libs](/libs) are the jar package and the dependency packages for the Bumo Java Encryption.
4. [src](/src)  is the source code for the Bumo Java Encryption.

## Environment

JDK 8 or above.

## Installation

#### Mode 1：Adding Dependencies to Maven Projects (Recommended)
To use the Bumo Java Encryption in a Maven project, just add the remote repository provided by Bumo to the maven configuration and add the corresponding dependency to pom.xml.

This article uses version 1.0.0 as an example

Maven remote repository
``` xml
<repository>
    <id>pubnexus</id>                
    <url>http://maven.bumo.io/content/groups/public/</url>
    <releases>
        <enabled>true</enabled>
    </releases>
    <snapshots>
        <enabled>true</enabled>
    </snapshots>
</repository>
```
Add the following in the dependencies tag：
``` xml
<dependency>
  <groupId>io.bumo</groupId>
  <artifactId>bumo-encryption</artifactId>
  <version>1.0.0</version>
</dependency>
```
#### Mode 2: Import the JAR Package in the Project
1. Download Bumo Java Encryption Development Kit
2. Unzip the development package
3. Import bumo-encryption-{version}.jar and the included libs jar into your project

## Example project
Bumo Java Encryption provides rich examples for developers' reference

[Sample document entry](docs/bumo_encryption.md "")