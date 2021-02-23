# SCION



[![Go Report Card](https://goreportcard.com/badge/github.com/sciontime/scion)](https://goreportcard.com/report/github.com/sciontime/scion)

[![License](https://img.shields.io/github/license/scionproto/scion.svg?maxAge=2592000)](https://github.com/scionproto/scion/blob/master/LICENSE)

Welcome to the open-source implementation of
[SCION](http://www.scion-architecture.net) (Scalability, Control and Isolation
On next-generation Networks), a future Internet architecture. SCION is the first
clean-slate Internet architecture designed to provide route control, failure
isolation, and explicit trust information for end-to-end communication. To find
out more about the project, please visit our [documentation
site](https://anapaya-scion.readthedocs-hosted.com/en/latest/).


## Connecting to the SCION Test Network

Join [SCIONLab](https://www.scionlab.org) if you're interested in playing with
SCION in an operational global test deployment of SCION. As part of the SCIONLab
project, we support [pre-built binaries as Debian
packages](https://docs.scionlab.org/content/install/).

## Building

To find out how to work with SCION, please visit our [documentation
site](https://anapaya-scion.readthedocs-hosted.com/en/latest/contribute.html#setting-up-the-development-environment)
for instructions on how to install build dependencies, build and run SCION.



## Contributing

Interested in contribution to the SCION project? Please visit us at
[contribute.rst](https://anapaya-scion.readthedocs-hosted.com/en/latest/contribute.html)
for more information about how you can do so.

## Scion Time / this fork

Join [SCIONLab](https://www.scionlab.org) if you're interested in playing with
SCION in an operational global test deployment of SCION.

As of 1.3.2021: This fork of [scionproto/scion](github.com/scionproto/scion) will be merged into [SCIONLab](https://www.scionlab.org) and [scionproto/scion](github.com/scionproto/scion). Scion Time implements the needed features to provide kernel and hardware timestamps to applications.

## Configuration
Scion Time has some additional directives for the dispatchers configuration file ([scion documentation
site](https://anapaya-scion.readthedocs-hosted.com/en/latest/contribute.html#setting-up-the-development-environment))

```SCION sciondAddr \<IPv4>:\<Port> (mandatory)```

```timestamp_rx``` activate Rx-Timestamps

```timestamp_tx``` activate Tx-Timesamps

```hwtimestamp```  the device to capture hw timestamps

```timestamp_udp6``` create timestamps for UDP6 ("false" is enforced)

```err_queue_chan_cap``` size of queue for Tx-Timestamps (10-1000 should be fine)

Example disp.toml:
```toml
[dispatcher]
id = "dispatcher"
delete_socket = true

timestamp_rx = true
timestamp_tx = true
hwtimestamp = "enp0s31f6"
timestamp_udp6 = false
err_queue_chan_cap = 1000

[metrics]
prometheus = "[127.0.0.1]:30441"

[features]

[log.console]
level = "debug"

```

## License

[![License](https://img.shields.io/github/license/scionproto/scion.svg?maxAge=2592000)](https://github.com/scionproto/scion/blob/master/LICENSE)
