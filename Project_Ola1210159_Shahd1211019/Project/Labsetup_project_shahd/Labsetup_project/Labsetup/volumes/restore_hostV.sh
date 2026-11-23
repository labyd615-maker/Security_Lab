#!/bin/bash
ip route del 192.168.53.0/24
ip route add default via 192.168.60.11
ip route
