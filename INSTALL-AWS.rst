..
    2021-09-24 - whartond

=============
Dalton in AWS
=============

General Install
---------------

The easiest way to get Dalton up and running is to use
`Docker <https://www.docker.com/get-docker>`__ and
`Docker Compose <https://docs.docker.com/compose/install/>`__
and then run:

.. code:: bash

    ./start-dalton.sh

All this and more are covered in the `README <README.rst#installing-and-running-dalton>`_.

This can be done almost anywhere, including the cloud.  The following
example shows how easy it is to get Dalton up and running in AWS
from scratch.

Install Dalton on an AWS EC2 instance
-------------------------------------

This example uses the **Amazon Linux 2 AMI**.

Notes
=====

Depending on how many Dalton Agents are running, rulesets, etc.:

- More than 8GB of storage is likely needed; configure for at least 12GB but more is recommended.
- 1GB memory will work (most of the time) but more is recommended; try at least twice that or more.

The following were done using the Amazon Linux 2 AMI on a
t2.micro instance (free tier).  The entire process took less
than half an hour, with the bulk of the time -- just under
24 mins -- spent in Step 4 doing the
initial download, build, and config of the containers.

Step 1: Install Docker
======================

.. code:: bash

    sudo yum update -y
    sudo amazon-linux-extras install docker -y
    sudo usermod -a -G docker ec2-user
    sudo chkconfig docker on
    sudo service docker start


**Now, log off and log back on**

Step 2: Install Docker Compose
==============================

.. code:: bash

    sudo curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose


Step 3: Download Dalton
=======================

.. code:: bash

    sudo yum install -y git
    git clone https://github.com/secureworks/dalton.git
    cd dalton

**(edit docker-compose.yml as desired)**

Step 4: Build and Run Dalton
============================

.. code:: bash

    ./start-dalton.sh
