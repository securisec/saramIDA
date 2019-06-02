<img src="saramida.png" width="150px">

[![Build Status](https://travis-ci.com/securisec/saramIDA.svg?branch=master)](https://travis-ci.com/securisec/saramIDA)

# saramIDA
This is the IDA Pro plugin for Saram. It has been tested on IDA v7 and is written in **Python 2** in order to support the idapython. 

This plugin is designed to be run from within the python interpretor of IDA itself.

## Installation
Clone this repository in your local IDA plugins directory. In the case of Linux or OSX, this is the `~/.idapro/plugins/` directory. 

Once cloned, the directory structure should look like this:
```
~/.idapro/plugins
    saramIDAHelpers/
    saramIDA.py
```

## Usage
To use this plugin, instantiate `saramIDA` from with the IDA python interpretor as such.
```py
saram = SaramIDA('avalidsaramtoken')
```

Then you can call the available methods like:
```py
saram.some_method().send() # .send() will send the data to the Saram server
```

## Avaialable methods

Presently, the following methods are available:
- decompile_function *Gets the decomplied code from a function*
- get_strings *Gets all the strings in a binary*
- function_comments *Get all user comments from a function*