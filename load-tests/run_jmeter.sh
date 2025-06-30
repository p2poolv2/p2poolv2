#!/usr/bin/bash

# uiScale is set to 2.0 for high DPI displays
# The log level for TCP protocol is set to DEBUG

jmeter -Dsun.java2d.uiScale=2.0 -Jlog_level.jmeter.protocol.tcp=DEBUG