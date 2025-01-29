#!/bin/bash
echo $(git rev-parse --short HEAD) > version.txt
git add version.txt