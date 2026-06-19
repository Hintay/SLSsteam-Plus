#!/bin/bash

CONFIG="$(cat "./res/config.toml")"

echo "static const char* defaultConfig = R\"($CONFIG)\";" > src/config_default.hpp
