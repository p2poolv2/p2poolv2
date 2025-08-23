# Rust Stratum v1 Server

This crate provides a stratum server that we are using in P2Poolv2.

The server firmware compatibility is driven by a community effort. As
more folks point their hardware, even just for a few minutes the web
page is updated to reflect the status. You can see the test results on
https://test.hydrapool.org

We have a load test setup ready for the stratum server and will soon
publish the results. The load testing is conducted using Apache jbench
that allows the most optimal use of a multi core hardware to model
traffic to a server. We use a mock bitcoind server that servers the
same blocktemplate and accepts any blocks that are submitted. You can
review the benchmark code under the ../load-tests/ directory.
