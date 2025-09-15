## This my journey to SIEM system understanding

## Targetted SIEM - GRAYLOG 
## Graylog:
    - Graylog is an opensource Security Information and Event Management (SIEM) system that offers performance on log collection, analysis, and performance. Graylog consists of multiple key features such as log aggregation, search & investigations, real-time system analysis. Common cases that graylog is used for is mainly security monitoring and compliance for detecting threats/vulnerabilites/security incidents and making sure regulatory requirements have organized log reporting.

    -Graylog offers mainly three types of deployment models: Graylog Open, Enterprise, and Cloud.


## System Setup
    - My system setup consist of:

        - Oracle VirtualBox:
            - Contains my ubuntu server onfiguration and setup
                - Storage: 25gb and 4 cpu core
                - Type of file; ISO
        - Deployment Model: Graylog Open
            - Deployed on Docker Container:
                - Handles docker, mongodb, and graylog services configurations


## Projects:
**Project 1: Basic Graylog configuration and creating input/indices**
    -- Goal of this project is to setup graylog and docker container and explore the SIEM dashboards and instances
        -- Familiarized myself with log ingestions.
        -- Created inputs with rule indices for receiving log messages from my Ubuntu Server via ssh connection.




