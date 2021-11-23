[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">

<h3 align="center">gniffer</h3>

  <p align="center">
    Simple, lightweight, and easy to use gopacket wrapper cli
    <br />
    <a href="https://github.com/strixeyecom/gniffer"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/strixeyecom/gniffer">View Demo</a>
    ·
    <a href="https://github.com/strixeyecom/gniffer/issues">Report Bug</a>
    ·
    <a href="https://github.com/strixeyecom/gniffer/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
   </li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->

## About The Project

This project was initially created to help to mirror requests for StrixEye Agent.

## Features

- Redirect incoming requests to a target web server
- Capture real time HTTP traffic from interfaces
- Capture HTTP traffic from a pcap file

### Built With

Thanks to maintainers and communities of the following projects for making development of this CLI easier. Full list of
dependencies can be found in go modules file.

* [Cobra](https://github.com/spf13/cobra)
* [Viper](https://github.com/spf13/viper)
* [gopacket](https://github.com/google/gopacket)
* [libpcap] (https://www.tcpdump.org/)

<!-- GETTING STARTED -->

## Getting Started

General information about setting up gniffer locally

### Requirements

Required software and installations.

* libpcap v1.10.0 or higher
* flex
* bison
* gcc

Install flex and bison via your package manager.Then, to install libpcap, run the following script, preferably as root:

```shell
wget -O libpcap-1.10.0.tar.gz http://www.tcpdump.org/release/libpcap-1.10.0.tar.gz
tar -xf libpcap-1.10.0.tar.gz
cd libpcap-1.10.0
./configure
make && make install
ldconfig
```

### Installation

#### Tarball

1. Download [latest-release] for your operating system/architecture
2. Unzip binary and place it somewhere in your path
3. Make it executable

#### Build

Other than Go version 1.16.+, StrixEye CLI has no dependencies/requirements.

Basic building process like the following would suffice.

```shell
   go build -o gniffer main.go
```

##### Docker

```shell
    docker pull gniffer:latest
```

<!-- ROADMAP -->

<!-- USAGE EXAMPLES -->

## Usage

### Shell

Following command will start sniffing loopback interface and redirect all incoming requests to target web server on
target.omer.beer

```shell
gniffer sniff proxy --target-protocol=https --target-host=target.omer.beer --target-port=443 -i lo
```

### Docker

The docker image comes as a command line utility, meaning you can access all cli commands.

```shell
docker run gniffer --help
```

Following command will start sniffing loopback interface and redirect all incoming requests to target web server on
target.omer.beer

```shell
docker run gniffer sniff proxy --target-protocol=https --target-host=akaunting.agent.strixeye.com --target-port=443 -i lo
```

_For more examples, please refer to the [Documentation](https://pkg.go.dev/strixeyecom/gniffer)_

## Roadmap

See the [open issues](https://github.com/strixeyecom/gniffer/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learned, inspire, and create. Any
contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache License 2.0 License. See `LICENSE` for more information.



<!-- CONTACT -->

## Contact

StrixEye - [@strixeye](https://twitter.com/strixeye) - help@strixeye.com

Project Link: [https://github.com/strixeyecom/gniffer](https://github.com/strixeyecom/gniffer)




<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/strixeyecom/gniffer.svg?style=for-the-badge

[contributors-url]: https://github.com/strixeyecom/gniffer/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/strixeyecom/gniffer.svg?style=for-the-badge

[forks-url]: https://github.com/strixeyecom/gniffer/network/members

[stars-shield]: https://img.shields.io/github/stars/strixeyecom/gniffer?style=for-the-badge

[stars-url]: https://github.com/strixeyecom/gniffer/stargazers

[issues-shield]: https://img.shields.io/github/issues/strixeyecom/gniffer.svg?style=for-the-badge

[issues-url]: https://github.com/strixeyecom/gniffer/issues

[license-shield]: https://img.shields.io/github/license/strixeyecom/gniffer.svg?style=for-the-badge

[license-url]: https://github.com/strixeyecom/gniffer/blob/master/LICENSE.txt

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555

[linkedin-url]: https://linkedin.com/in/strixeye

[latest-release]: https://github.com/strixeyecom/gniffer/releases