#!/bin/bash
ip route del default
ip route add 192.168.53.0/24 via 192.168.60.11
ip route
