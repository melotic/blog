---
title: "CI Pipeline Duration Prediction"
date: 2022-07-17T15:24:58-07:00
draft: true
---

As part of my summer internship at Microsoft, I work on the .NET Engineering team, where we manage the common build infrastructure for most of .NET Core.

This notably includes the build process, and the *common* CI pipelines that all of the .NET repositories use. We also manage a tool called [Helix](https://github.com/dotnet/arcade/blob/main/Documentation/Helix.md) which is our massively distributed system for running any work (mostly tests) on loads of different machines (Linux, Windows, Mac, Android, iPhone, x86-64, ARM, etc).

