# Cealgull Backend Testing Suite

<p align="center"><a href="https://k6.io/"><img src="https://raw.githubusercontent.com/grafana/k6/master/assets/logo.svg" alt="k6" width="258" height="210" /></a></p>

Cealgull Dev Team leverages k6 load testing suite to build API Port testing formula.

Note that all the scripts are written in typescript.

## Getting Started

We use community-extended k6 to provide dashboard and influxdb powered statistics gathering.

For dependencies, you need xk6.


```console
go install go.k6.io/xk6/cmd/xk6@latest
```

The build customized k6 with dashboard and influxdb v2 enabled using the following command.

```console
xk6 build --with github.com/szkiba/xk6-dashboard@latest --with github.com/grafana/xk6-output-influxdb
```

In the k6 directory, install all dependencies and build the test suite.

```console
yarn install && yarn build

```

Finally, use k6 to run test inside the dist directory.

```console
k6 run sample_test.js --out dashboard

```

The testing option is fully documented in [k6 documentation](https://k6.io/docs/).
